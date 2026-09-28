<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Domain\Identity\Enums\UserState;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

final class EffectiveAdministratorGuard
{
    public function __construct(private readonly IdentityEventRecorder $events) {}

    /**
     * Lock the common invariant row before any role, assignment, or user rows.
     * Every Task 6 mutation that can affect administrator effectiveness uses this mutex.
     */
    public function lockMutex(): Role
    {
        return Role::query()
            ->where('code', 'administrator')
            ->lockForUpdate()
            ->firstOrFail();
    }

    public function assertExists(
        User $actor,
        User $subject,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        $roles = Role::query()
            ->where('is_active', true)
            ->orderBy('id')
            ->lockForUpdate()
            ->with('permissions:id,code')
            ->get()
            ->keyBy('id');
        $users = User::query()
            ->where('state', UserState::Active)
            ->orderBy('id')
            ->lockForUpdate()
            ->get()
            ->keyBy('id');
        $assignments = RoleAssignment::query()
            ->whereNull('application_id')
            ->whereNull('revoked_at')
            ->where('starts_at', '<=', now())
            ->where(static function ($query): void {
                $query->whereNull('ends_at')->orWhere('ends_at', '>', now());
            })
            ->orderBy('id')
            ->lockForUpdate()
            ->get();

        if ($this->containsEffectiveAdministrator($users, $roles, $assignments)) {
            return;
        }

        DB::afterRollBack(function () use ($actor, $subject, $ipAddress, $userAgent, $correlationId): void {
            $this->events->security(
                'identity.administrator.last_protected',
                $actor,
                $subject,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
        });

        throw new DomainRuleViolation(
            'last_effective_administrator',
            ['The final effective administrator cannot be made ineffective.'],
        );
    }

    /**
     * @param  Collection<int, User>  $users
     * @param  Collection<int, Role>  $roles
     * @param  Collection<int, RoleAssignment>  $assignments
     */
    private function containsEffectiveAdministrator(
        Collection $users,
        Collection $roles,
        Collection $assignments,
    ): bool {
        /** @var array<int, array<string, true>> $permissionsByUser */
        $permissionsByUser = [];

        foreach ($assignments as $assignment) {
            if (! $users->has($assignment->user_id)) {
                continue;
            }

            $role = $roles->get($assignment->role_id);

            if (! $role instanceof Role) {
                continue;
            }

            foreach ($role->permissions as $permission) {
                $permissionsByUser[$assignment->user_id][$permission->code] = true;
            }
        }

        foreach ($permissionsByUser as $permissionCodes) {
            if (isset($permissionCodes['admin.users'], $permissionCodes['admin.roles'])) {
                return true;
            }
        }

        return false;
    }
}
