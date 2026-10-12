<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;

final class AccountLockout
{
    public function recordFailure(User $user): bool
    {
        return DB::transaction(function () use ($user): bool {
            $lockedUser = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $now = CarbonImmutable::now();
            $cutoff = $now->subMinutes((int) config('identity.lockout.window_minutes'));
            /** @var list<string> $history */
            $history = $lockedUser->auth_failure_timestamps ?? [];
            $history = array_values(array_filter(
                $history,
                static fn (string $timestamp): bool => CarbonImmutable::parse($timestamp)->greaterThanOrEqualTo($cutoff),
            ));
            $history[] = $now->format('Y-m-d H:i:s.u');
            $locked = count($history) >= (int) config('identity.lockout.attempts');
            $user->forceFill([
                'auth_failure_timestamps' => $history,
                'failed_auth_attempts' => count($history),
                'failed_auth_window_started_at' => $history[0],
                'locked_until' => $locked
                    ? $now->addMinutes((int) config('identity.lockout.minutes'))
                    : $lockedUser->locked_until,
            ])->save();

            if ($locked) {
                $this->invalidateAuthenticationState($user);
            }

            return $locked;
        }, 3);
    }

    public function reset(User $user): void
    {
        DB::transaction(function () use ($user): void {
            User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $user->forceFill([
                'auth_failure_timestamps' => [],
                'failed_auth_attempts' => 0,
                'failed_auth_window_started_at' => null,
                'locked_until' => null,
            ])->save();
        }, 3);
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
