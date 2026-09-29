<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Domain\Identity\Enums\UserState;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Support\Exceptions\DomainRuleViolation;
use Carbon\CarbonInterface;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use LogicException;

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
            ->whereNotNull('email_verified_at')
            ->whereNotNull('activated_at')
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

    public function assertAdministratorAssignmentsUnbounded(User $user): void
    {
        $assignments = RoleAssignment::query()
            ->where('user_id', $user->getKey())
            ->whereNull('application_id')
            ->whereNull('revoked_at')
            ->whereHas('role', static fn ($query) => $query->where('is_active', true))
            ->with(['role.permissions' => static function ($query): void {
                $query->whereIn('code', ['admin.users', 'admin.roles']);
            }])
            ->orderBy('id')
            ->lockForUpdate()
            ->get();

        foreach ($assignments as $assignment) {
            [$startsAt, $endsAt, $role] = $this->assignmentState($assignment);

            if (! $startsAt->isFuture() && $endsAt === null) {
                continue;
            }

            $assignmentCodes = $role->permissions->pluck('code');
            $overlappingCodes = collect();

            foreach ($assignments as $other) {
                if ($other->is($assignment)) {
                    continue;
                }

                [$otherStartsAt, $otherEndsAt, $otherRole] = $this->assignmentState($other);
                $overlaps = ($endsAt === null || $otherStartsAt->lt($endsAt))
                    && ($otherEndsAt === null || $startsAt->lt($otherEndsAt));

                if (! $overlaps) {
                    continue;
                }

                $overlappingCodes = $overlappingCodes
                    ->merge($otherRole->permissions->pluck('code'))
                    ->unique();
            }

            $combinedCodes = $assignmentCodes->merge($overlappingCodes)->unique();
            $assignmentParticipatesInAdministration = $assignmentCodes->contains('admin.users')
                || $assignmentCodes->contains('admin.roles');

            if ($assignmentParticipatesInAdministration
                && $combinedCodes->contains('admin.users')
                && $combinedCodes->contains('admin.roles')) {
                throw new DomainRuleViolation(
                    'bounded_effective_administrator_assignment',
                    ['Effective administrator assignments must begin immediately and cannot expire.'],
                );
            }
        }
    }

    /** @return array{CarbonInterface, CarbonInterface|null, Role} */
    private function assignmentState(RoleAssignment $assignment): array
    {
        $startsAt = $assignment->getAttribute('starts_at');
        $endsAt = $assignment->getAttribute('ends_at');
        $role = $assignment->getRelation('role');

        if (! $startsAt instanceof CarbonInterface
            || ($endsAt !== null && ! $endsAt instanceof CarbonInterface)
            || ! $role instanceof Role) {
            throw new LogicException('Administrator assignment state was not hydrated correctly.');
        }

        return [$startsAt, $endsAt, $role];
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
