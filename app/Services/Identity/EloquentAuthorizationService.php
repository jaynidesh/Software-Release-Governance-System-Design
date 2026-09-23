<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\AuthorizationCatalog;
use App\Domain\Identity\Enums\PermissionScope;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Models\UserMfaMethod;

final class EloquentAuthorizationService implements AuthorizationService
{
    public function __construct(private readonly CurrentAuthSessionValidator $sessions) {}

    public function allows(
        User $user,
        string $permission,
        ?Application $application,
        bool $requiresFreshReauthentication,
    ): bool {
        $scope = AuthorizationCatalog::permissions()[$permission] ?? null;

        if ($scope === null) {
            return false;
        }

        $currentUser = User::query()
            ->whereKey($user->getKey())
            ->where('state', UserState::Active)
            ->first();

        if ($currentUser === null) {
            return false;
        }

        $currentApplication = $this->currentApplication($scope, $application);

        if ($scope === PermissionScope::Application && $currentApplication === null) {
            return false;
        }

        if ($scope === PermissionScope::Global && $application !== null) {
            return false;
        }

        $isPrivileged = $this->isPrivileged($permission);
        $authSession = $this->sessions->current(
            $currentUser,
            $isPrivileged,
            $requiresFreshReauthentication,
        );

        if ($authSession === null) {
            return false;
        }

        if ($isPrivileged && ! $this->hasConfirmedMfa($currentUser)) {
            return false;
        }

        $assignments = RoleAssignment::query()
            ->select(['id', 'user_id', 'role_id', 'application_id'])
            ->with([
                'role' => static function ($role) use ($permission): void {
                    $role->where('is_active', true)->with([
                        'permissions' => static function ($permissions) use ($permission): void {
                            $permissions->select(['permissions.id', 'code', 'scope_type'])
                                ->where('code', $permission);
                        },
                    ]);
                },
            ])
            ->where('user_id', $currentUser->getKey())
            ->where('starts_at', '<=', now())
            ->whereNull('revoked_at')
            ->where(static function ($query): void {
                $query->whereNull('ends_at')->orWhere('ends_at', '>', now());
            })
            ->when(
                $scope === PermissionScope::Global,
                static fn ($query) => $query->whereNull('application_id'),
                static fn ($query) => $query->where(static function ($scopeQuery) use ($currentApplication): void {
                    $scopeQuery->whereNull('application_id')
                        ->orWhere('application_id', $currentApplication?->getKey());
                }),
            )
            ->get();

        return $assignments->contains(static function (RoleAssignment $assignment) use ($permission): bool {
            return $assignment->role?->permissions->contains('code', $permission) === true;
        });
    }

    private function currentApplication(
        PermissionScope $scope,
        ?Application $application,
    ): ?Application {
        if ($scope !== PermissionScope::Application || $application === null) {
            return null;
        }

        return Application::query()
            ->whereKey($application->getKey())
            ->where('is_active', true)
            ->first();
    }

    private function isPrivileged(string $permission): bool
    {
        foreach ((array) config('identity.privileged_permissions', []) as $privilegedPermission) {
            if (! is_string($privilegedPermission)) {
                continue;
            }

            if (str_ends_with($privilegedPermission, '.')) {
                if (str_starts_with($permission, $privilegedPermission)) {
                    return true;
                }

                continue;
            }

            if ($permission === $privilegedPermission) {
                return true;
            }
        }

        return false;
    }

    private function hasConfirmedMfa(User $user): bool
    {
        return UserMfaMethod::query()
            ->where('user_id', $user->getKey())
            ->whereNotNull('confirmed_at')
            ->whereNull('disabled_at')
            ->exists();
    }
}
