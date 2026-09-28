<?php

declare(strict_types=1);

namespace App\Application\Identity\Assignments;

use App\Contracts\Identity\AuthorizationService;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\PrivilegeChangeInvalidator;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class RevokeRoleAssignment
{
    public function __construct(
        private readonly AuthorizationService $authorization,
        private readonly EffectiveAdministratorGuard $administrators,
        private readonly PrivilegeChangeInvalidator $invalidator,
        private readonly IdentityEventRecorder $events,
    ) {}

    public function handle(
        User $actor,
        RoleAssignment $assignment,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): RoleAssignment {
        return DB::transaction(function () use (
            $actor,
            $assignment,
            $ipAddress,
            $userAgent,
            $correlationId,
        ): RoleAssignment {
            $this->administrators->lockMutex();
            $lockedAssignment = RoleAssignment::query()
                ->whereKey($assignment->getKey())
                ->lockForUpdate()
                ->firstOrFail();
            $users = User::query()
                ->whereKey([(int) $actor->getKey(), (int) $lockedAssignment->user_id])
                ->orderBy('id')
                ->lockForUpdate()
                ->get()
                ->keyBy('id');
            $lockedActor = $users->get($actor->getKey());
            $lockedTarget = $users->get($lockedAssignment->user_id);

            if (! $lockedActor instanceof User || ! $lockedTarget instanceof User
                || ! $this->authorization->allows($lockedActor, 'admin.roles', null, true)) {
                throw new AuthorizationException;
            }

            if ($lockedActor->is($lockedTarget)) {
                throw new DomainRuleViolation(
                    'self_role_assignment',
                    ['A different administrator must change your role assignments.'],
                );
            }

            $lockedAssignment->forceFill([
                'revoked_at' => now(),
                'revoked_by' => $lockedActor->id,
            ])->save();
            $this->administrators->assertExists(
                $lockedActor,
                $lockedTarget,
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $this->invalidator->invalidate($lockedTarget);
            $this->events->security(
                'identity.role_assignment.revoked',
                $lockedActor,
                $lockedTarget,
                ['assignment_public_id' => $lockedAssignment->public_id],
                $ipAddress,
                $userAgent,
                $correlationId,
            );

            return $lockedAssignment;
        }, 3);
    }
}
