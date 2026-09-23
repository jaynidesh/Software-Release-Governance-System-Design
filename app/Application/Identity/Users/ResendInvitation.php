<?php

declare(strict_types=1);

namespace App\Application\Identity\Users;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Services\Identity\AccountLockout;
use App\Services\Identity\IdentityEventRecorder;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class ResendInvitation
{
    public function __construct(
        private readonly AuthorizationService $authorization,
        private readonly AccountLockout $lockout,
        private readonly IdentityEventRecorder $events,
    ) {}

    public function handle(
        User $actor,
        User $user,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): User {
        return DB::transaction(function () use (
            $actor,
            $user,
            $ipAddress,
            $userAgent,
            $correlationId,
        ): User {
            $this->authorize($actor);
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();

            if (UserState::from((string) $lockedUser->getRawOriginal('state')) !== UserState::Invited) {
                throw new DomainRuleViolation(
                    'invitation_not_resendable',
                    ['Only invited users can receive another invitation.'],
                );
            }

            $this->lockout->invalidateAuthenticationState($lockedUser);
            $lockedUser->forceFill([
                'invited_at' => now(),
                'invitation_expires_at' => now()->addDays((int) config('identity.invitation_ttl_days')),
            ])->save();
            $this->events->security(
                'identity.invitation.resent',
                $actor,
                $lockedUser,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $lockedUser->notify(new ActivationInvitationNotification);

            return $lockedUser;
        }, 3);
    }

    private function authorize(User $actor): void
    {
        if (! $this->authorization->allows($actor, 'admin.users', null, true)) {
            throw new AuthorizationException;
        }
    }
}
