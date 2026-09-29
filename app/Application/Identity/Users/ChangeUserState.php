<?php

declare(strict_types=1);

namespace App\Application\Identity\Users;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\PrivilegeChangeInvalidator;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class ChangeUserState
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
        UserState $state,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): User {
        return DB::transaction(function () use (
            $actor,
            $target,
            $state,
            $ipAddress,
            $userAgent,
            $correlationId,
        ): User {
            $this->administrators->lockMutex();
            $users = User::query()
                ->whereKey([(int) $actor->getKey(), (int) $target->getKey()])
                ->orderBy('id')
                ->lockForUpdate()
                ->get()
                ->keyBy('id');
            $lockedActor = $users->get($actor->getKey());
            $lockedTarget = $users->get($target->getKey());

            if (! $lockedActor instanceof User || ! $lockedTarget instanceof User
                || ! $this->authorization->allows($lockedActor, 'admin.users', null, true)) {
                throw new AuthorizationException;
            }

            $currentState = UserState::from((string) $lockedTarget->getRawOriginal('state'));

            if ($state === UserState::Invited) {
                throw new DomainRuleViolation(
                    'administrator_invitation_transition_forbidden',
                    ['Invitation state is managed by activation and reactivation workflows.'],
                );
            }

            if ($currentState === UserState::Invited && $state === UserState::Active) {
                throw new DomainRuleViolation(
                    'invitation_activation_requires_otp',
                    ['Invited users must complete passwordless activation.'],
                );
            }

            $requiresActivation = $currentState === UserState::Deactivated
                || $lockedTarget->email_verified_at === null
                || $lockedTarget->activated_at === null;
            $effectiveState = $state === UserState::Active && $requiresActivation
                ? UserState::Invited
                : $state;
            $attributes = ['state' => $effectiveState];

            if ($currentState === UserState::Deactivated || $effectiveState === UserState::Deactivated) {
                $attributes += [
                    'email_verified_at' => null,
                    'activated_at' => null,
                ];
            }

            if ($effectiveState === UserState::Invited) {
                $attributes += [
                    'email_verified_at' => null,
                    'activated_at' => null,
                    'invited_at' => now(),
                    'invitation_expires_at' => now()->addDays((int) config('identity.invitation_ttl_days')),
                ];
            }

            $lockedTarget->forceFill($attributes)->save();
            $this->administrators->assertExists(
                $lockedActor,
                $lockedTarget,
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $this->invalidator->invalidate($lockedTarget);
            $this->events->security(
                'identity.user.state_changed',
                $lockedActor,
                $lockedTarget,
                ['state' => $effectiveState->value],
                $ipAddress,
                $userAgent,
                $correlationId,
            );

            if ($effectiveState === UserState::Invited) {
                DB::afterCommit(static fn () => $lockedTarget->notify(new ActivationInvitationNotification));
            }

            return $lockedTarget;
        }, 3);
    }
}
