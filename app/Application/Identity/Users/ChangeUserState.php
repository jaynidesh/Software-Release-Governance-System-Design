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

            if ($currentState === UserState::Invited && $state === UserState::Active) {
                throw new DomainRuleViolation(
                    'invitation_activation_requires_otp',
                    ['Invited users must complete passwordless activation.'],
                );
            }

            $effectiveState = $currentState === UserState::Deactivated && $state === UserState::Active
                ? UserState::Invited
                : $state;
            $attributes = ['state' => $effectiveState];

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
