<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;

final class AccountLockout
{
    public function recordFailure(User $user): bool
    {
        $windowStartedAt = $user->failed_auth_window_started_at;
        $withinWindow = $windowStartedAt !== null
            && now()->subMinutes((int) config('identity.lockout.window_minutes'))
                ->lessThanOrEqualTo($windowStartedAt);

        $failedAttempts = $withinWindow ? $user->failed_auth_attempts + 1 : 1;

        $user->forceFill([
            'failed_auth_attempts' => $failedAttempts,
            'failed_auth_window_started_at' => $withinWindow ? $windowStartedAt : now(),
        ]);

        $locked = $failedAttempts >= (int) config('identity.lockout.attempts');

        if ($locked) {
            $user->forceFill([
                'locked_until' => now()->addMinutes((int) config('identity.lockout.minutes')),
            ]);
        }

        $user->save();

        if ($locked) {
            $this->invalidateAuthenticationState($user);
        }

        return $locked;
    }

    public function reset(User $user): void
    {
        $user->forceFill([
            'failed_auth_attempts' => 0,
            'failed_auth_window_started_at' => null,
            'locked_until' => null,
        ])->save();
    }

    public function isLocked(User $user): bool
    {
        return $user->locked_until !== null && now()->isBefore($user->locked_until);
    }

    public function invalidateAuthenticationState(User $user): void
    {
        AuthChallenge::query()
            ->where('user_id', $user->getKey())
            ->whereNull('consumed_at')
            ->whereNull('invalidated_at')
            ->update(['invalidated_at' => now()]);

        PendingAuthentication::query()
            ->where('user_id', $user->getKey())
            ->whereNull('completed_at')
            ->whereNull('invalidated_at')
            ->update(['invalidated_at' => now()]);
    }
}
