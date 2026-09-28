<?php

declare(strict_types=1);

namespace App\Application\Identity\Users;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use App\Support\Exceptions\DomainRuleViolation;
use Carbon\CarbonInterface;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class CreateInvitedUser
{
    public function __construct(
        private readonly AuthorizationService $authorization,
        private readonly EffectiveAdministratorGuard $administrators,
        private readonly IdentityEventRecorder $events,
    ) {}

    /**
     * @param  array{employee_number?: string|null, name: string, email: string, timezone: string}  $attributes
     * @param  list<array{role: Role, application: Application|null, starts_at: CarbonInterface, ends_at: CarbonInterface|null}>  $initialAssignments
     */
    public function handle(
        User $actor,
        array $attributes,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
        array $initialAssignments = [],
    ): User {
        $this->authorize($actor);

        if ($initialAssignments !== []) {
            $this->authorizeRoleAdministration($actor);
        }

        return DB::transaction(function () use (
            $actor,
            $attributes,
            $ipAddress,
            $userAgent,
            $correlationId,
            $initialAssignments,
        ): User {
            if ($initialAssignments !== []) {
                $this->administrators->lockMutex();
            }

            $lockedActor = User::query()->whereKey($actor->getKey())->lockForUpdate()->firstOrFail();
            $this->authorize($lockedActor);

            if ($initialAssignments !== []) {
                $this->authorizeRoleAdministration($lockedActor);
            }

            $user = User::query()->create([
                'employee_number' => $attributes['employee_number'] ?? null,
                'name' => trim($attributes['name']),
                'email' => $attributes['email'],
                'state' => UserState::Invited,
                'timezone' => $attributes['timezone'],
                'email_verified_at' => null,
                'invited_at' => now(),
                'invitation_expires_at' => now()->addDays((int) config('identity.invitation_ttl_days')),
                'activated_at' => null,
            ]);

            foreach ($initialAssignments as $initialAssignment) {
                $role = $initialAssignment['role'];
                $application = $initialAssignment['application'];
                $lockedRole = Role::query()->whereKey($role->getKey())->lockForUpdate()->firstOrFail();
                $lockedApplication = $application !== null
                    ? Application::query()->whereKey($application->getKey())->lockForUpdate()->firstOrFail()
                    : null;

                if (! $lockedRole->is_active || ($lockedApplication !== null && ! $lockedApplication->is_active)) {
                    throw new DomainRuleViolation(
                        'inactive_initial_assignment',
                        ['Initial assignments require active roles and applications.'],
                    );
                }

                $startsAt = $initialAssignment['starts_at'];
                $endsAt = $initialAssignment['ends_at'];
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

                RoleAssignment::query()->create([
                    'user_id' => $user->id,
                    'role_id' => $lockedRole->id,
                    'application_id' => $lockedApplication?->id,
                    'starts_at' => $startsAt,
                    'ends_at' => $endsAt,
                    'assigned_by' => $lockedActor->id,
                ]);
                $this->events->security(
                    'identity.role_assignment.assigned',
                    $lockedActor,
                    $user,
                    [
                        'role_public_id' => $lockedRole->public_id,
                        'application_public_id' => $lockedApplication?->public_id,
                    ],
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );
            }
            $this->events->security(
                'identity.invitation.created',
                $lockedActor,
                $user,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            DB::afterCommit(static fn () => $user->notify(new ActivationInvitationNotification));

            return $user;
        }, 3);
    }

    private function authorize(User $actor): void
    {
        if (! $this->authorization->allows($actor, 'admin.users', null, true)) {
            throw new AuthorizationException;
        }
    }

    private function authorizeRoleAdministration(User $actor): void
    {
        if (! $this->authorization->allows($actor, 'admin.roles', null, true)) {
            throw new AuthorizationException;
        }
    }
}
