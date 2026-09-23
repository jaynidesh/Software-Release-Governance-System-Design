<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Mfa\VerifyPendingMfa;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Models\UserRecoveryCode;
use App\Notifications\Identity\RecoveryCodeUsedNotification;
use App\Services\Identity\RecoveryCodeHasher;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Validation\ValidationException;
use OTPHP\TOTP;
use Tests\TestCase;

final class RecoveryCodeAuthenticationTest extends TestCase
{
    use RefreshDatabase;

    public function test_totp_completion_is_monotonic_and_resets_failures_only_after_full_success(): void
    {
        $this->travelTo('2026-09-23 10:00:10');
        $user = User::factory()->privileged()->mfaConfirmed()->create([
            'failed_auth_attempts' => 2,
            'failed_auth_window_started_at' => now(),
        ]);
        $method = $user->mfaMethods()->sole();
        $code = TOTP::createFromSecret($method->secret)->now();
        $pending = $this->beginPending($user);

        $this->post('/login/mfa', ['code' => $code])->assertRedirect('/');

        $this->assertAuthenticatedAs($user);
        self::assertNotNull($method->refresh()->last_accepted_timestep);
        self::assertNotNull($pending->refresh()->completed_at);
        self::assertSame(0, $user->refresh()->failed_auth_attempts);
        $this->assertDatabaseHas('login_events', [
            'user_id' => $user->id,
            'result_code' => 'AUTHENTICATION_SUCCEEDED',
        ]);
        $this->assertDatabaseHas('security_events', [
            'subject_user_id' => $user->id,
            'event_code' => 'identity.authentication.succeeded',
        ]);

        $this->logOutBrowser();
        $this->beginPending($user);
        $this->post('/login/mfa', ['code' => $code])
            ->assertRedirect('/login/mfa')
            ->assertSessionHasErrors(['code' => 'The authentication code is invalid or expired.']);
        self::assertSame(1, $user->refresh()->failed_auth_attempts);
        $this->assertGuest();
    }

    public function test_action_rechecks_session_binding_and_current_privilege(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $method = $user->mfaMethods()->sole();
        $pending = $this->beginPending($user);
        $pending->update(['session_id_hmac' => str_repeat('f', 64)]);

        $this->expectException(ValidationException::class);
        $this->app->make(VerifyPendingMfa::class)->handle(
            $pending,
            TOTP::createFromSecret($method->secret)->now(),
            null,
            null,
            null,
        );
    }

    public function test_recovery_code_is_consumed_once_and_low_count_warning_and_notice_are_emitted(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $method = $user->mfaMethods()->sole();
        $plain = 'ABCD-EFGH-IJKL';
        UserRecoveryCode::query()->create([
            'user_mfa_method_id' => $method->id,
            'code_hmac' => $this->app->make(RecoveryCodeHasher::class)->hash($plain, $method->id),
        ]);
        $pending = $this->beginPending($user);
        Queue::fake([SendQueuedNotifications::class]);

        $this->post('/login/mfa', ['code' => $plain])
            ->assertRedirect('/')
            ->assertSessionHas('warning', 'You have 0 recovery codes remaining. Generate a new set now.');

        self::assertNotNull(UserRecoveryCode::query()->sole()->used_at);
        self::assertNotNull($pending->refresh()->completed_at);
        Queue::assertPushed(SendQueuedNotifications::class, static function (SendQueuedNotifications $job): bool {
            return $job->notification instanceof RecoveryCodeUsedNotification;
        });

    }

    public function test_totp_and_recovery_failures_share_the_account_lockout(): void
    {
        config()->set('identity.lockout.attempts', 2);
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $this->beginPending($user);

        $this->post('/login/mfa', ['code' => '000000']);
        $this->post('/login/mfa', ['code' => 'NOT-A-RECOVERY-CODE']);

        self::assertNotNull($user->refresh()->locked_until);
        self::assertNotNull(PendingAuthentication::query()->sole()->invalidated_at);
        $this->assertGuest();
    }

    private function beginPending(User $user): PendingAuthentication
    {
        $this->post('/login/otp', ['email' => $user->email]);
        $challenge = AuthChallenge::query()->whereNull('consumed_at')->latest('id')->firstOrFail();
        $challenge->update(['delivered_at' => now()]);
        $this->post('/login/verify', ['code' => $this->queuedOtpCode()]);
        $this->withCookie((string) config('session.cookie'), $this->sessionStore()->getId());

        return PendingAuthentication::query()->whereNull('completed_at')->whereNull('invalidated_at')->sole();
    }

    private function queuedOtpCode(): string
    {
        /** @var array{data: array{command: string}} $payload */
        $payload = json_decode((string) DB::table('jobs')->latest('id')->value('payload'), true, flags: JSON_THROW_ON_ERROR);
        $serialized = $this->app->make(Encrypter::class)->decrypt($payload['data']['command']);
        self::assertIsString($serialized);
        $job = unserialize($serialized, ['allowed_classes' => true]);
        self::assertInstanceOf(SendQueuedNotifications::class, $job);

        return $job->notification->code;
    }

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }

    private function logOutBrowser(): void
    {
        auth()->logout();
        $this->sessionStore()->invalidate();
        $this->sessionStore()->regenerateToken();
        $this->withCookie((string) config('session.cookie'), $this->sessionStore()->getId());
    }
}
