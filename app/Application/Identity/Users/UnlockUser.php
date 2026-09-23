<?php

declare(strict_types=1);

namespace App\Application\Identity\Users;

use App\Contracts\Identity\AuthorizationService;
use App\Models\User;
use App\Notifications\Identity\AccountUnlockedNotification;
use App\Services\Identity\AccountLockout;
use App\Services\Identity\IdentityEventRecorder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class UnlockUser
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
            $this->lockout->reset($lockedUser);
            $this->lockout->invalidateAuthenticationState($lockedUser);
            $lockedUser->increment('session_version');
            $lockedUser->refresh();
            $this->events->security(
                'identity.account.unlocked',
                $actor,
                $lockedUser,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $lockedUser->notify(new AccountUnlockedNotification);

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
