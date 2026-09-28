<?php

declare(strict_types=1);

namespace App\Application\Identity\Roles;

use App\Contracts\Identity\AuthorizationService;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\PrivilegeChangeInvalidator;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class ChangeRoleState
{
    public function __construct(
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
    }
}
