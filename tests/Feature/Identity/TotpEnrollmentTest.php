<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Mfa\BeginTotpEnrollment;
use App\Application\Identity\Mfa\ConfirmTotpEnrollment;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\UserState;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Models\UserRecoveryCode;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use OTPHP\TOTP;
use Tests\TestCase;

final class TotpEnrollmentTest extends TestCase
{
    use RefreshDatabase;

    public function test_enrollment_displays_a_local_svg_and_manual_key_once_and_encrypts_the_secret(): void
    {
        $user = User::factory()->privileged()->create();
        $this->pendingFor($user);

        $response = $this->get('/login/mfa/enroll')->assertOk()->assertHeader('Cache-Control', 'no-store, private');
        $method = UserMfaMethod::query()->sole();
        $secret = $method->secret;

        $response->assertSee($secret)->assertSee('<svg', false);
        self::assertNotSame($secret, $method->getRawOriginal('secret'));
        self::assertNull($method->confirmed_at);

        $this->get('/login/mfa/enroll')
            ->assertOk()
            ->assertDontSee($secret)
            ->assertDontSee('<svg', false);
    }

    public function test_confirmation_generates_one_time_recovery_codes_before_activation(): void
    {
        $user = User::factory()->invited()->create();
        $this->grantPrivilege($user);
        $pending = $this->pendingFor($user, AuthenticationPurpose::Activation);
        $this->get('/login/mfa/enroll')->assertOk();
        $method = UserMfaMethod::query()->sole();
        $code = TOTP::createFromSecret($method->secret)->now();

        $response = $this->post('/login/mfa/enroll', ['code' => $code]);

        $response->assertOk()->assertSee('Store these recovery codes');
        self::assertSame((int) config('identity.totp.recovery_code_count'), UserRecoveryCode::query()->count());
        self::assertNull($method->refresh()->confirmed_at);
        self::assertSame(UserState::Invited, $user->refresh()->state);
        self::assertNull($pending->refresh()->completed_at);

        preg_match_all('/data-recovery-code="([A-Z0-9-]+)"/', $response->getContent(), $matches);
        self::assertCount((int) config('identity.totp.recovery_code_count'), $matches[1]);
        foreach ($matches[1] as $plainCode) {
            self::assertStringNotContainsString($plainCode, UserRecoveryCode::query()->pluck('code_hmac')->implode(' '));
        }

        $this->get('/login/mfa/enroll')->assertRedirect('/login/mfa/recovery-codes');
        $this->get('/login/mfa/recovery-codes')->assertOk()->assertDontSee($matches[1][0]);

        $this->post('/login/mfa/recovery-codes', ['acknowledged' => '1'])->assertRedirect('/');
        $this->assertAuthenticatedAs($user);
        self::assertNotNull($method->refresh()->confirmed_at);
        self::assertNotNull($pending->refresh()->completed_at);
        self::assertSame(UserState::Active, $user->refresh()->state);
    }

    public function test_abandoned_unconfirmed_enrollment_is_replaced_after_its_ttl(): void
    {
        config()->set('identity.totp.unconfirmed_ttl_minutes', 5);
        $user = User::factory()->privileged()->create();
        $this->pendingFor($user);
        $this->get('/login/mfa/enroll');
        $old = UserMfaMethod::query()->sole();
        $oldSecret = $old->secret;
        $old->forceFill(['created_at' => now()->subMinutes(6)])->save();

        $response = $this->get('/login/mfa/enroll')->assertOk();

        self::assertSame(1, UserMfaMethod::query()->count());
        self::assertNotSame($oldSecret, UserMfaMethod::query()->sole()->secret);
        $response->assertDontSee($oldSecret);
    }

    public function test_expired_confirmed_setup_is_purged_before_recovery_acknowledgment(): void
    {
        config()->set('identity.totp.unconfirmed_ttl_minutes', 5);
        $user = User::factory()->privileged()->create();
        $this->pendingFor($user);
        $this->get('/login/mfa/enroll');
        $method = UserMfaMethod::query()->sole();
        $this->post('/login/mfa/enroll', [
            'code' => TOTP::createFromSecret($method->secret)->now(),
        ])->assertOk();
        self::assertGreaterThan(0, $method->recoveryCodes()->count());
        $method->forceFill(['created_at' => now()->subMinutes(6)])->save();

        $this->get('/login/mfa/recovery-codes')->assertRedirect('/login/mfa/enroll');

        self::assertFalse(UserMfaMethod::query()->whereKey($method->id)->exists());
        self::assertSame(0, UserRecoveryCode::query()->count());
        $this->get('/login/mfa/enroll')->assertOk()->assertSee('Manual setup key');
    }

    public function test_new_primary_sequence_cannot_acknowledge_an_earlier_sequences_recovery_codes(): void
    {
        $user = User::factory()->privileged()->create();
        $firstPending = $this->pendingFor($user);
        $this->get('/login/mfa/enroll');
        $method = UserMfaMethod::query()->sole();
        $this->post('/login/mfa/enroll', [
            'code' => TOTP::createFromSecret($method->secret)->now(),
        ])->assertOk();
        self::assertGreaterThan(0, $method->recoveryCodes()->count());

        $secondPending = $this->pendingFor($user);

        self::assertNotSame($firstPending->id, $secondPending->id);
        self::assertNotNull($firstPending->refresh()->invalidated_at);
        $this->get('/login/mfa/recovery-codes')->assertRedirect('/login/mfa/enroll');
        self::assertSame(0, UserRecoveryCode::query()->count());
    }

    public function test_acknowledgment_action_purges_expired_setup_and_recovery_codes(): void
    {
        config()->set('identity.totp.unconfirmed_ttl_minutes', 5);
        $user = User::factory()->privileged()->create();
        $pending = $this->pendingFor($user);
        $this->get('/login/mfa/enroll');
        $method = UserMfaMethod::query()->sole();
        $this->post('/login/mfa/enroll', [
            'code' => TOTP::createFromSecret($method->secret)->now(),
        ])->assertOk();
        $method->forceFill(['created_at' => now()->subMinutes(6)])->save();

        try {
            $this->app->make(ConfirmTotpEnrollment::class)->acknowledge($pending, null, null, null);
            self::fail('Expired enrollment acknowledgment was accepted.');
        } catch (ValidationException) {
            // Expected generic rejection after the locked cleanup commits.
        }

        self::assertFalse(UserMfaMethod::query()->whereKey($method->id)->exists());
        self::assertSame(0, UserRecoveryCode::query()->count());
        $this->assertGuest();
    }

    public function test_enrollment_failures_share_the_account_lockout_and_invalidate_pending_state(): void
    {
        config()->set('identity.lockout.attempts', 2);
        $user = User::factory()->privileged()->create();
        $pending = $this->pendingFor($user);
        $this->get('/login/mfa/enroll')->assertOk();

        $this->post('/login/mfa/enroll', ['code' => '000000']);
        $this->post('/login/mfa/enroll', ['code' => '000000']);

        self::assertNotNull($user->refresh()->locked_until);
        self::assertNotNull($pending->refresh()->invalidated_at);
    }

    public function test_begin_enrollment_action_rechecks_the_pending_session_binding(): void
    {
        $user = User::factory()->privileged()->create();
        $pending = $this->pendingFor($user);
        $pending->update(['session_id_hmac' => str_repeat('e', 64)]);

        $this->expectException(ValidationException::class);
        $this->app->make(BeginTotpEnrollment::class)->handle($pending);
    }

    private function pendingFor(User $user, AuthenticationPurpose $purpose = AuthenticationPurpose::Login): PendingAuthentication
    {
        $this->post('/login/otp', ['email' => $user->email]);
        $challenge = AuthChallenge::query()->latest('id')->firstOrFail();
        self::assertSame($purpose, $challenge->purpose);
        $challenge->update(['delivered_at' => now()]);
        $this->post('/login/verify', ['code' => $this->queuedCode()]);
        $this->withCookie((string) config('session.cookie'), $this->sessionStore()->getId());

        return PendingAuthentication::query()
            ->whereNull('completed_at')
            ->whereNull('invalidated_at')
            ->latest('id')
            ->sole();
    }

    private function grantPrivilege(User $user): void
    {
        $privileged = User::factory()->privileged()->create();
        $source = $privileged->roleAssignments()->sole();
        RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $source->role_id,
            'application_id' => null,
            'starts_at' => now(),
        ]);
    }

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }

    private function queuedCode(): string
    {
        /** @var array{data: array{command: string}} $payload */
        $payload = json_decode((string) DB::table('jobs')->latest('id')->value('payload'), true, flags: JSON_THROW_ON_ERROR);
        $serialized = $this->app->make(Encrypter::class)->decrypt($payload['data']['command']);
        self::assertIsString($serialized);
        $job = unserialize($serialized, ['allowed_classes' => true]);
        self::assertInstanceOf(SendQueuedNotifications::class, $job);

        return $job->notification->code;
    }
}
