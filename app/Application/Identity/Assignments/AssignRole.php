<?php

declare(strict_types=1);

namespace App\Application\Identity\Assignments;

use App\Contracts\Identity\AuthorizationService;
use App\Models\Application;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\PrivilegeChangeInvalidator;
use App\Support\Exceptions\DomainRuleViolation;
use Carbon\CarbonInterface;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class AssignRole
{
    public function __construct(
        private readonly AuthorizationService $authorization,
        private readonly EffectiveAdministratorGuard $administrators,
        private readonly PrivilegeChangeInvalidator $invalidator,
        private readonly IdentityEventRecorder $events,
    ) {}

    public function handle(
        User $actor,
        User $target,
        Role $role,
        ?Application $application,
        CarbonInterface $startsAt,
        ?CarbonInterface $endsAt,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): RoleAssignment {
        return DB::transaction(function () use (
            $actor,
            $target,
            $role,
            $application,
            $startsAt,
            $endsAt,
            $ipAddress,
            $userAgent,
            $correlationId,
        ): RoleAssignment {
            $this->administrators->lockMutex();
            $users = User::query()
                ->whereKey([(int) $actor->getKey(), (int) $target->getKey()])
                ->orderBy('id')
                ->lockForUpdate()
                ->get()
                ->keyBy('id');
            $lockedActor = $users->get($actor->getKey());
            $lockedTarget = $users->get($target->getKey());

            if (! $lockedActor instanceof User || ! $lockedTarget instanceof User) {
                throw new AuthorizationException;
            }

            $this->authorize($lockedActor);

            if ($lockedActor->is($lockedTarget)) {
                throw new DomainRuleViolation(
                    'self_role_assignment',
                    ['A different administrator must change your role assignments.'],
                );
            }

            $lockedRole = Role::query()->whereKey($role->getKey())->lockForUpdate()->firstOrFail();

            if (! $lockedRole->is_active) {
                throw new DomainRuleViolation('inactive_role_assignment', ['Only active roles can be assigned.']);
            }

            $lockedApplication = null;

            if ($application !== null) {
                $lockedApplication = Application::query()
                    ->whereKey($application->getKey())
                    ->lockForUpdate()
                    ->firstOrFail();

                if (! $lockedApplication->is_active) {
                    throw new DomainRuleViolation(
                        'inactive_application_assignment',
                        ['Activate the application before assigning a scoped role.'],
                    );
                }
            }

            if ($endsAt !== null && $endsAt->lessThanOrEqualTo($startsAt)) {
                throw new DomainRuleViolation('invalid_assignment_period', ['Assignment end must follow its start.']);
            }

            $adminCodes = $lockedRole->permissions()
                ->whereIn('code', ['admin.users', 'admin.roles'])
                ->pluck('code');

            if ($lockedApplication === null
                && $adminCodes->contains('admin.users')
                && $adminCodes->contains('admin.roles')
                && ($startsAt->isFuture() || $endsAt !== null)) {
                throw new DomainRuleViolation(
                    'bounded_effective_administrator_assignment',
                    ['Effective administrator assignments must begin immediately and cannot expire.'],
                );
            }

            $assignment = RoleAssignment::query()->firstOrNew([
                'user_id' => $lockedTarget->id,
                'role_id' => $lockedRole->id,
                'application_id' => $lockedApplication?->id,
            ]);
            $assignment->forceFill([
                'starts_at' => $startsAt,
                'ends_at' => $endsAt,
                'revoked_at' => null,
                'assigned_by' => $lockedActor->id,
                'revoked_by' => null,
            ])->save();

            $this->invalidator->invalidate($lockedTarget);
            $this->events->security(
                'identity.role_assignment.assigned',
                $lockedActor,
                $lockedTarget,
                [
                    'role_public_id' => $lockedRole->public_id,
                    'application_public_id' => $lockedApplication?->public_id,
                ],
                $ipAddress,
                $userAgent,
                $correlationId,
            );

            return $assignment;
        }, 3);
    }

    private function authorize(User $actor): void
    {
        if (! $this->authorization->allows($actor, 'admin.roles', null, true)) {
            throw new AuthorizationException;
        }
    }
}
