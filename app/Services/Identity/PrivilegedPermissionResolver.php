<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Domain\Identity\Enums\PermissionScope;
use App\Models\Application;
use App\Models\Permission;
use App\Models\User;
use App\Models\UserMfaMethod;

final class PrivilegedPermissionResolver
{
    /** @var list<string> */
    private const BASELINE = [
        'admin.',
        'production.approve',
        'signoff.production',
        'maker_checker.override.approve',
    ];

    public function isPrivileged(string $permissionCode): bool
    {
        foreach ($this->rules() as $rule) {
            if ($permissionCode === $rule
                || (str_ends_with($rule, '.') && str_starts_with($permissionCode, $rule))) {
                return true;
            }
        }

        return false;
    }

    public function userIsPrivileged(User $user): bool
    {
        return Permission::query()
            ->select('permissions.code')
            ->join('role_permissions', 'role_permissions.permission_id', '=', 'permissions.id')
            ->join('roles', 'roles.id', '=', 'role_permissions.role_id')
            ->join('role_assignments', 'role_assignments.role_id', '=', 'roles.id')
            ->leftJoin('applications', 'applications.id', '=', 'role_assignments.application_id')
            ->where('role_assignments.user_id', $user->getKey())
            ->where('roles.is_active', true)
            ->whereNull('roles.deleted_at')
            ->where('role_assignments.starts_at', '<=', now())
            ->whereNull('role_assignments.revoked_at')
            ->where(static function ($query): void {
                $query->whereNull('role_assignments.ends_at')
                    ->orWhere('role_assignments.ends_at', '>', now());
            })
            ->where(static function ($query): void {
                $query->where(static function ($global): void {
                    $global->where('permissions.scope_type', PermissionScope::Global)
                        ->whereNull('role_assignments.application_id');
                })->orWhere(static function ($application): void {
                    $application->where('permissions.scope_type', PermissionScope::Application)
                        ->where(static function ($assignment): void {
                            $assignment->where(static function ($scoped): void {
                                $scoped->whereNotNull('role_assignments.application_id')
                                    ->where('applications.is_active', true);
                            })->orWhere(static function ($global): void {
                                $global->whereNull('role_assignments.application_id')
                                    ->whereExists(static function ($activeApplications): void {
                                        $activeApplications->selectRaw('1')
                                            ->from((new Application)->getTable().' as active_applications')
                                            ->where('active_applications.is_active', true);
                                    });
                            });
                        });
                });
            })
            ->pluck('permissions.code')
            ->contains(fn (mixed $code): bool => is_string($code) && $this->isPrivileged($code));
    }

    public function authenticationRequiresMfa(User $user, AuthenticationPurpose $purpose): bool
    {
        if ($this->userIsPrivileged($user)) {
            return true;
        }

        return $purpose === AuthenticationPurpose::Reauthentication
            && UserMfaMethod::query()
                ->where('user_id', $user->getKey())
                ->where('type', MfaMethodType::Totp)
                ->whereNotNull('confirmed_at')
                ->whereNull('disabled_at')
                ->exists();
    }

    /** @return list<string> */
    private function rules(): array
    {
        $configured = array_filter(
            (array) config('identity.additional_privileged_permissions', []),
            static fn (mixed $rule): bool => is_string($rule) && $rule !== '',
        );

        // Accept the full configured list for compatibility, while always restoring the immutable baseline.
        $legacyConfigured = array_filter(
            (array) config('identity.privileged_permissions', []),
            static fn (mixed $rule): bool => is_string($rule) && $rule !== '',
        );

        return array_values(array_unique([...self::BASELINE, ...$configured, ...$legacyConfigured]));
    }
}
