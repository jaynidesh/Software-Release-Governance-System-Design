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
            $users = User::query()
                ->whereKey([(int) $actor->getKey(), (int) $user->getKey()])
                ->orderBy('id')
                ->lockForUpdate()
                ->get()
                ->keyBy('id');
            $lockedActor = $users->get($actor->getKey());
            $lockedUser = $users->get($user->getKey());

            if (! $lockedActor instanceof User || ! $lockedUser instanceof User) {
                throw new AuthorizationException;
            }

            $this->authorize($lockedActor);
            $this->lockout->reset($lockedUser);
            $this->lockout->invalidateAuthenticationState($lockedUser);
            $lockedUser->increment('session_version');
            $lockedUser->refresh();
            $this->events->security(
                'identity.account.unlocked',
                $lockedActor,
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
