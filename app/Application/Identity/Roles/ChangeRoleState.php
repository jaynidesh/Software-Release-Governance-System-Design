<?php

declare(strict_types=1);

namespace App\Application\Identity\Roles;

use App\Contracts\Identity\AuthorizationService;
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

final class ChangeRoleState
{
    public function __construct(private readonly IdentityMutationBoundary $mutationBoundary,
        private readonly AuthorizationService $authorization,
        private readonly EffectiveAdministratorGuard $administrators,
        private readonly PrivilegeChangeInvalidator $invalidator,
        private readonly IdentityEventRecorder $events,
    ) {}

    public function handle(
        User $actor,
        Role $role,
        bool $isActive,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): Role {
        return $this->mutationBoundary->run(function () use ($actor, $role, $isActive, $ipAddress, $userAgent, $correlationId): Role {
            return DB::transaction(function () use (
                $actor,
                $role,
                $isActive,
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

                if ($isActive && ! $lockedRole->is_active
                    && $lockedRole->permissions()->exists()
                    && RoleAssignment::query()
                        ->where('user_id', $lockedActor->id)
                        ->where('role_id', $lockedRole->id)
                        ->whereNull('revoked_at')
                        ->lockForUpdate()
                        ->exists()) {
                    throw new DomainRuleViolation(
                        'actor_assigned_role_activation',
                        ['A different administrator must activate a role assigned to you.'],
                    );
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
                $lockedRole->update(['is_active' => $isActive]);
                if ($isActive) {
                    foreach ($affectedUsers as $affectedUser) {
                        $this->administrators->assertAdministratorAssignmentsUnbounded($affectedUser);
                    }
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
                    'identity.role.state_changed',
                    $lockedActor,
                    null,
                    ['role_public_id' => $lockedRole->public_id, 'is_active' => $isActive],
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                return $lockedRole;
            }, 3);
        }, $actor, self::class, $ipAddress, $userAgent, $correlationId);
    }
}
