<?php

declare(strict_types=1);

namespace App\Application\Identity\Roles;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\AuthorizationCatalog;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\IdentityMutationBoundary;
use App\Services\Identity\PrivilegeChangeInvalidator;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class SyncRolePermissions
{
    public function __construct(private readonly IdentityMutationBoundary $mutationBoundary,
        private readonly AuthorizationService $authorization,
        private readonly EffectiveAdministratorGuard $administrators,
        private readonly PrivilegeChangeInvalidator $invalidator,
        private readonly IdentityEventRecorder $events,
    ) {}

    /** @param list<int> $permissionIds */
    public function handle(
        User $actor,
        Role $role,
        array $permissionIds,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): Role {
        return $this->mutationBoundary->run(function () use ($actor, $role, $permissionIds, $ipAddress, $userAgent, $correlationId): Role {
            return DB::transaction(function () use (
                $actor,
                $role,
                $permissionIds,
                $ipAddress,
                $userAgent,
                $correlationId,
            ): Role {
                $this->administrators->lockMutex();
                $lockedActor = User::query()->whereKey($actor->getKey())->lockForUpdate()->firstOrFail();

                if (! $this->authorization->allows($lockedActor, 'admin.roles', null, true)) {
                    throw new AuthorizationException;
                }

                $lockedRole = Role::query()->whereKey($role->getKey())->lockForUpdate()->firstOrFail();
                $actorHasRole = RoleAssignment::query()
                    ->where('user_id', $lockedActor->id)
                    ->where('role_id', $lockedRole->id)
                    ->whereNull('revoked_at')
                    ->lockForUpdate()
                    ->exists();

                if ($actorHasRole) {
                    throw new DomainRuleViolation(
                        'actor_assigned_role_edit',
                        ['A different administrator must change permissions for a role assigned to you.'],
                    );
                }

                $permissions = Permission::query()->whereKey($permissionIds)->orderBy('id')->lockForUpdate()->get();

                if ($permissions->count() !== count(array_unique($permissionIds))
                    || $permissions->contains(static fn (Permission $permission): bool => ! array_key_exists(
                        $permission->code,
                        AuthorizationCatalog::permissions(),
                    ))) {
                    throw new DomainRuleViolation(
                        'noncanonical_permission',
                        ['Roles may contain only canonical permissions.'],
                    );
                }

                if ((string) $lockedRole->getRawOriginal('code') === 'administrator') {
                    $selectedCodes = $permissions->pluck('code');
                    $missingAdminCode = collect(array_keys(AuthorizationCatalog::permissions()))
                        ->filter(static fn (string $code): bool => str_starts_with($code, 'admin.'))
                        ->contains(static fn (string $code): bool => ! $selectedCodes->contains($code));

                    if ($missingAdminCode) {
                        throw new DomainRuleViolation(
                            'administrator_permissions_immutable',
                            ['The Administrator role must retain every canonical admin permission.'],
                        );
                    }
                }

                $userIds = RoleAssignment::query()
                    ->where('role_id', $lockedRole->id)
                    ->whereNull('revoked_at')
                    ->orderBy('user_id')
                    ->lockForUpdate()
                    ->pluck('user_id')
                    ->unique()
                    ->values();
                $affectedUsers = User::query()->whereKey($userIds)->orderBy('id')->lockForUpdate()->get();
                $lockedRole->permissions()->sync($permissions->modelKeys());
                foreach ($affectedUsers as $affectedUser) {
                    $this->administrators->assertAdministratorAssignmentsUnbounded($affectedUser);
                }
                $this->administrators->assertExists(
                    $lockedActor,
                    $lockedActor,
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                foreach ($affectedUsers as $affectedUser) {
                    $this->invalidator->invalidate($affectedUser);
                }

                $this->events->security(
                    'identity.role.permissions_changed',
                    $lockedActor,
                    null,
                    ['role_public_id' => $lockedRole->public_id, 'permission_count' => $permissions->count()],
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                return $lockedRole->load('permissions');
            }, 3);
        }, $actor, self::class, $ipAddress, $userAgent, $correlationId);
    }
}
