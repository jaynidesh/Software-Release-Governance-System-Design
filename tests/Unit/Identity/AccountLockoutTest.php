<?php

declare(strict_types=1);

namespace Tests\Unit\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Services\Identity\AccountLockout;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class AccountLockoutTest extends TestCase
{
    use RefreshDatabase;

    public function test_failures_roll_forward_without_forgetting_recent_attempts(): void
    {
        $this->travelTo('2026-10-05 10:00:00');
        config()->set('identity.lockout.attempts', 5);
        $user = User::factory()->active()->create();
        $lockout = $this->app->make(AccountLockout::class);
        foreach ([0, 14, 14, 14, 16, 16] as $index => $minute) {
            $this->travelTo('2026-10-05 10:'.str_pad((string) $minute, 2, '0', STR_PAD_LEFT).':00');
            self::assertSame($index === 5, $lockout->recordFailure($user->fresh()));
        }
        self::assertSame(5, $user->refresh()->failed_auth_attempts);
        self::assertSame('2026-10-05 10:14:00', $user->failed_auth_window_started_at?->format('Y-m-d H:i:s'));
    }

    public function test_rolling_window_includes_exact_boundary_prunes_older_attempts_and_resets_history(): void
    {
        $this->travelTo('2026-10-05 10:00:00');
        $user = User::factory()->active()->create();
        $lockout = $this->app->make(AccountLockout::class);
        $lockout->recordFailure($user);
        $this->travel(15)->minutes();
        $lockout->recordFailure($user);
        self::assertSame(2, $user->refresh()->failed_auth_attempts);
        $this->travel(1)->seconds();
        $lockout->recordFailure($user);
        self::assertSame(2, $user->refresh()->failed_auth_attempts);
        $lockout->reset($user);
        $lockout->recordFailure($user);
        self::assertSame(1, $user->refresh()->failed_auth_attempts);
    }

    public function test_failures_use_a_sliding_window_and_lock_at_the_configured_threshold(): void
    {
        $this->travelTo('2026-09-22 10:00:00');
        config()->set('identity.lockout.attempts', 3);
        config()->set('identity.lockout.window_minutes', 15);
        config()->set('identity.lockout.minutes', 30);
        $user = User::factory()->active()->create();
        $lockout = $this->app->make(AccountLockout::class);

        self::assertFalse($lockout->recordFailure($user));
        self::assertSame(1, $user->refresh()->failed_auth_attempts);

        $this->travel(16)->minutes();
        self::assertFalse($lockout->recordFailure($user));
        self::assertSame(1, $user->refresh()->failed_auth_attempts);
        self::assertFalse($lockout->recordFailure($user));
        self::assertTrue($lockout->recordFailure($user));

        $user->refresh();
        self::assertSame(3, $user->failed_auth_attempts);
        self::assertSame('2026-09-22 10:46:00', $user->locked_until?->format('Y-m-d H:i:s'));
    }

    public function test_locking_invalidates_open_challenges_and_pending_authentication(): void
    {
        config()->set('identity.lockout.attempts', 1);
        $user = User::factory()->active()->create();
        $challenge = $this->createChallenge($user);
        $pending = PendingAuthentication::query()->create([
            'user_id' => $user->id,
            'auth_challenge_id' => $challenge->id,
            'purpose' => AuthenticationPurpose::Login,
            'session_id_hmac' => str_repeat('b', 64),
            'user_session_version' => $user->session_version,
            'expires_at' => now()->addMinutes(10),
        ]);

        self::assertTrue($this->app->make(AccountLockout::class)->recordFailure($user));

        self::assertNotNull($challenge->refresh()->invalidated_at);
        self::assertNotNull($pending->refresh()->invalidated_at);
    }

    public function test_reset_clears_the_complete_failure_window(): void
    {
        $user = User::factory()->locked()->create();

        $this->app->make(AccountLockout::class)->reset($user);

        $user->refresh();
        self::assertSame(0, $user->failed_auth_attempts);
        self::assertNull($user->failed_auth_window_started_at);
        self::assertNull($user->locked_until);
    }

    private function createChallenge(User $user): AuthChallenge
    {
        return AuthChallenge::query()->create([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'code_hmac' => str_repeat('a', 64),
            'expires_at' => now()->addMinutes(10),
        ]);
    }
}
