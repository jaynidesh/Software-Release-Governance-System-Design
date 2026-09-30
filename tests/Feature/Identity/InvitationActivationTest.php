<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Domain\Identity\AuthorizationCatalog;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\UserState;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Services\Identity\OtpHasher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class InvitationActivationTest extends TestCase
{
    use RefreshDatabase;

    #[DataProvider('invalidChallengeStates')]
    public function test_verification_rejects_every_invalid_challenge_with_one_message(string $state): void
    {
        $user = User::factory()->active()->create();
        [$challenge, $code] = $this->challengeFor($user, AuthenticationPurpose::Login);
        $this->makeChallengeInvalid($challenge, $state);
        $purpose = $state === 'purpose-mismatch'
            ? AuthenticationPurpose::Activation
            : AuthenticationPurpose::Login;

        $response = $this->withSession([
            'identity.auth_challenge' => $challenge->public_id,
            'identity.auth_purpose' => $purpose->value,
        ])->post('/login/verify', ['code' => $code]);

        $response->assertRedirect('/login/verify')
            ->assertSessionHasErrors(['code' => 'The code is invalid or expired.'])
            ->assertHeader('Cache-Control', 'no-store, private');
        $this->assertGuest();
    }

    /** @return array<string, array{string}> */
    public static function invalidChallengeStates(): array
    {
        return [
            'undelivered' => ['undelivered'],
            'expired' => ['expired'],
            'consumed' => ['consumed'],
            'invalidated' => ['invalidated'],
            'purpose mismatch' => ['purpose-mismatch'],
        ];
    }

    public function test_wrong_code_increments_shared_failures_and_exhausts_the_challenge(): void
    {
        config()->set('identity.otp.max_attempts', 3);
        config()->set('identity.lockout.attempts', 5);
        $user = User::factory()->active()->create();
        [$challenge] = $this->challengeFor($user, AuthenticationPurpose::Login, delivered: true);

        foreach (range(1, 3) as $attempt) {
            $this->withSession([
                'identity.auth_challenge' => $challenge->public_id,
                'identity.auth_purpose' => AuthenticationPurpose::Login->value,
            ])->post('/login/verify', ['code' => '000000'])
                ->assertSessionHasErrors(['code' => 'The code is invalid or expired.']);
        }

        self::assertSame(3, $challenge->refresh()->failed_attempts);
        self::assertNotNull($challenge->invalidated_at);
        self::assertSame(3, $user->refresh()->failed_auth_attempts);
        self::assertNull($user->locked_until);
        $this->assertDatabaseHas('security_events', [
            'subject_user_id' => $user->id,
            'event_code' => 'identity.authentication.failed',
        ]);
    }

    public function test_shared_failure_threshold_locks_the_account_and_invalidates_all_open_state(): void
    {
        config()->set('identity.otp.max_attempts', 10);
        config()->set('identity.lockout.attempts', 2);
        $user = User::factory()->active()->create();
        [$challenge] = $this->challengeFor($user, AuthenticationPurpose::Login, delivered: true);
        PendingAuthentication::query()->create([
            'user_id' => $user->id,
            'auth_challenge_id' => $challenge->id,
            'purpose' => AuthenticationPurpose::Activation,
            'session_id_hmac' => str_repeat('f', 64),
            'user_session_version' => $user->session_version,
            'expires_at' => now()->addMinutes(10),
        ]);

        foreach (range(1, 2) as $attempt) {
            $this->withSession([
                'identity.auth_challenge' => $challenge->public_id,
                'identity.auth_purpose' => AuthenticationPurpose::Login->value,
            ])->post('/login/verify', ['code' => '000000']);
        }

        self::assertNotNull($user->refresh()->locked_until);
        self::assertNotNull($challenge->refresh()->invalidated_at);
        self::assertSame(0, PendingAuthentication::query()->whereNull('invalidated_at')->count());
    }

    public function test_successful_login_consumes_once_regenerates_session_and_resets_failures(): void
    {
        $user = User::factory()->active()->create([
            'failed_auth_attempts' => 2,
            'failed_auth_window_started_at' => now(),
        ]);
        [$challenge, $code] = $this->challengeFor($user, AuthenticationPurpose::Login, delivered: true);
        $this->withSession([
            'identity.auth_challenge' => $challenge->public_id,
            'identity.auth_purpose' => AuthenticationPurpose::Login->value,
            'identity.otp_resend_available_at' => now()->addMinute()->getTimestampMs(),
        ]);
        $oldSessionId = $this->sessionStore()->getId();

        $response = $this->post('/login/verify', ['code' => $code]);

        $response->assertRedirect('/')->assertHeader('Cache-Control', 'no-store, private');
        $response->assertSessionMissing('identity.otp_resend_available_at');
        $this->assertAuthenticatedAs($user);
        self::assertNotSame($oldSessionId, $this->sessionStore()->getId());
        self::assertNotNull($challenge->refresh()->consumed_at);
        self::assertSame(0, $user->refresh()->failed_auth_attempts);
        self::assertNotNull($user->last_login_at);

        auth()->logout();
        $this->withSession([
            'identity.auth_challenge' => $challenge->public_id,
            'identity.auth_purpose' => AuthenticationPurpose::Login->value,
        ])->post('/login/verify', ['code' => $code])
            ->assertSessionHasErrors(['code' => 'The code is invalid or expired.']);
        $this->assertGuest();
    }

    public function test_invited_ordinary_user_is_activated_only_after_valid_delivery(): void
    {
        $user = User::factory()->invited()->create();
        [$challenge, $code] = $this->challengeFor($user, AuthenticationPurpose::Activation, delivered: true);

        $this->withSession([
            'identity.auth_challenge' => $challenge->public_id,
            'identity.auth_purpose' => AuthenticationPurpose::Activation->value,
        ])->post('/login/verify', ['code' => $code])->assertRedirect('/');

        $user->refresh();
        self::assertSame(UserState::Active, $user->state);
        self::assertNotNull($user->email_verified_at);
        self::assertNotNull($user->activated_at);
        $this->assertAuthenticatedAs($user);
        $this->assertDatabaseHas('security_events', [
            'subject_user_id' => $user->id,
            'event_code' => 'identity.invitation.activated',
        ]);
    }

    public function test_privileged_primary_success_creates_session_bound_pending_state_without_login(): void
    {
        $user = User::factory()->privileged()->create([
            'failed_auth_attempts' => 2,
            'failed_auth_window_started_at' => now(),
        ]);
        [$challenge, $code] = $this->challengeFor($user, AuthenticationPurpose::Login, delivered: true);
        $this->withSession([
            'identity.auth_challenge' => $challenge->public_id,
            'identity.auth_purpose' => AuthenticationPurpose::Login->value,
            'identity.otp_resend_available_at' => now()->addMinute()->getTimestampMs(),
        ]);
        $oldSessionId = $this->sessionStore()->getId();

        $response = $this->post('/login/verify', ['code' => $code]);

        $response->assertRedirect('/login/mfa/enroll')
            ->assertSessionHas('identity.pending_authentication')
            ->assertSessionMissing('identity.auth_challenge')
            ->assertSessionMissing('identity.otp_resend_available_at');
        $this->assertGuest();
        self::assertNotSame($oldSessionId, $this->sessionStore()->getId());
        $pending = PendingAuthentication::query()->sole();
        self::assertSame($user->id, $pending->user_id);
        self::assertSame($challenge->id, $pending->auth_challenge_id);
        self::assertSame($user->session_version, $pending->user_session_version);
        self::assertSame(
            $this->app->make(OtpHasher::class)->hashSessionId($this->sessionStore()->getId()),
            $pending->session_id_hmac,
        );
        self::assertSame($pending->public_id, session('identity.pending_authentication'));
        self::assertSame(2, $user->fresh()->failed_auth_attempts);
    }

    public function test_privileged_invitation_remains_invited_until_secondary_authentication(): void
    {
        $user = User::factory()->invited()->create();
        $this->grantPrivilegedPermission($user);
        [$challenge, $code] = $this->challengeFor($user, AuthenticationPurpose::Activation, delivered: true);

        $this->withSession([
            'identity.auth_challenge' => $challenge->public_id,
            'identity.auth_purpose' => AuthenticationPurpose::Activation->value,
        ])->post('/login/verify', ['code' => $code]);

        $user->refresh();
        self::assertSame(UserState::Invited, $user->state);
        self::assertNotNull($user->email_verified_at);
        self::assertNull($user->activated_at);
        $this->assertGuest();
        self::assertSame(1, PendingAuthentication::query()->count());
    }

    public function test_state_change_after_request_prevents_authentication(): void
    {
        $user = User::factory()->active()->create();
        [$challenge, $code] = $this->challengeFor($user, AuthenticationPurpose::Login, delivered: true);
        $user->update(['state' => UserState::Suspended]);

        $this->withSession([
            'identity.auth_challenge' => $challenge->public_id,
            'identity.auth_purpose' => AuthenticationPurpose::Login->value,
        ])->post('/login/verify', ['code' => $code])
            ->assertSessionHasErrors(['code' => 'The code is invalid or expired.']);

        $this->assertGuest();
        self::assertNull($challenge->refresh()->consumed_at);
    }

    /** @return array{AuthChallenge, string} */
    private function challengeFor(
        User $user,
        AuthenticationPurpose $purpose,
        bool $delivered = false,
    ): array {
        $code = '123456';
        $reference = strtolower((string) Str::ulid());
        $challenge = new AuthChallenge([
            'user_id' => $user->id,
            'purpose' => $purpose,
            'code_hmac' => $this->app->make(OtpHasher::class)->hash($code, $reference, $user->id, $purpose),
            'expires_at' => now()->addMinutes(10),
            'delivered_at' => $delivered ? now() : null,
        ]);
        $challenge->public_id = $reference;
        $challenge->save();

        return [$challenge, $code];
    }

    private function makeChallengeInvalid(AuthChallenge $challenge, string $state): void
    {
        match ($state) {
            'undelivered', 'purpose-mismatch' => null,
            'expired' => $challenge->update(['expires_at' => now()->subSecond()]),
            'consumed' => $challenge->update(['consumed_at' => now()]),
            'invalidated' => $challenge->update(['invalidated_at' => now()]),
        };

        if ($state !== 'undelivered') {
            $challenge->update(['delivered_at' => now()]);
        }
    }

    private function grantPrivilegedPermission(User $user): void
    {
        $role = Role::factory()->create();
        $permission = Permission::query()->create([
            'code' => 'admin.users',
            'description' => 'Administer users.',
            'scope_type' => AuthorizationCatalog::permissions()['admin.users'],
        ]);
        $role->permissions()->attach($permission);
        RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
        ]);
    }

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }
}
