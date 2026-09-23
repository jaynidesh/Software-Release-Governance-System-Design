<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Mfa\RegenerateRecoveryCodes;
use App\Application\Identity\Mfa\ResetUserMfa;
use App\Application\Identity\Mfa\RotateTotp;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Models\UserRecoveryCode;
use App\Notifications\Identity\RecoveryCodesRegeneratedNotification;
use App\Services\Identity\RecoveryCodeHasher;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use OTPHP\TOTP;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class MfaResetTest extends TestCase
{
    use RefreshDatabase;

    public function test_reset_requires_a_different_freshly_authorized_administrator(): void
    {
        $actor = User::factory()->privileged()->mfaConfirmed()->create();
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $permission === 'admin.users' && $requiresFreshReauthentication;
            }
        });

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(ResetUserMfa::class)->handle($actor, $actor, null, null, null);
    }

    public function test_reset_invalidates_mfa_recovery_pending_challenges_sessions_and_session_version(): void
    {
        $actor = User::factory()->privileged()->mfaConfirmed()->create();
        $target = User::factory()->privileged()->mfaConfirmed()->create();
        $method = $target->mfaMethods()->sole();
        UserRecoveryCode::query()->create([
            'user_mfa_method_id' => $method->id,
            'code_hmac' => str_repeat('a', 64),
        ]);
        $challenge = AuthChallenge::query()->create([
            'user_id' => $target->id,
            'purpose' => 'LOGIN',
            'code_hmac' => str_repeat('b', 64),
            'expires_at' => now()->addMinute(),
        ]);
        PendingAuthentication::query()->create([
            'user_id' => $target->id,
            'auth_challenge_id' => $challenge->id,
            'purpose' => 'LOGIN',
            'session_id_hmac' => str_repeat('c', 64),
            'user_session_version' => $target->session_version,
            'expires_at' => now()->addMinute(),
        ]);
        AuthSession::query()->create([
            'session_id' => 'target-session',
            'user_id' => $target->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'mfa_authenticated_at' => now(),
            'reauthenticated_at' => now(),
            'user_session_version' => $target->session_version,
        ]);
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return true;
            }
        });

        $this->app->make(ResetUserMfa::class)->handle($actor, $target, '127.0.0.1', 'Test', 'correlation');

        self::assertNotNull($method->refresh()->disabled_at);
        self::assertSame(0, UserRecoveryCode::query()->count());
        self::assertNotNull($challenge->refresh()->invalidated_at);
        self::assertSame(0, PendingAuthentication::query()->whereNull('invalidated_at')->count());
        self::assertSame(0, AuthSession::query()->where('user_id', $target->id)->count());
        self::assertSame(2, $target->refresh()->session_version);
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.mfa.reset', 'actor_id' => $actor->id]);
    }

    public function test_reset_rechecks_authorization_after_actor_and_target_are_locked(): void
    {
        $actor = User::factory()->privileged()->mfaConfirmed()->create();
        $target = User::factory()->privileged()->mfaConfirmed()->create();
        $transactionLevel = DB::transactionLevel();
        $this->app->bind(AuthorizationService::class, fn () => new class($transactionLevel) implements AuthorizationService
        {
            public function __construct(private readonly int $transactionLevel) {}

            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return DB::transactionLevel() > $this->transactionLevel
                    && $permission === 'admin.users'
                    && $requiresFreshReauthentication;
            }
        });

        $this->app->make(ResetUserMfa::class)->handle($actor, $target, null, null, null);

        self::assertNotNull($target->mfaMethods()->sole()->disabled_at);
    }

    public function test_reset_allows_successful_privileged_reenrollment(): void
    {
        $actor = User::factory()->privileged()->mfaConfirmed()->create();
        $target = User::factory()->privileged()->mfaConfirmed()->create();
        $oldSecret = $target->mfaMethods()->sole()->secret;
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return true;
            }
        });
        $this->app->make(ResetUserMfa::class)->handle($actor, $target, null, null, null);

        $this->post('/login/otp', ['email' => $target->email]);
        $challenge = AuthChallenge::query()->where('user_id', $target->id)->latest('id')->firstOrFail();
        $challenge->update(['delivered_at' => now()]);
        $this->post('/login/verify', ['code' => $this->queuedOtpCode()])->assertRedirect('/login/mfa/enroll');
        $this->withCookie((string) config('session.cookie'), $this->app->make(Session::class)->getId());
        $response = $this->get('/login/mfa/enroll')->assertOk()->assertSee('Manual setup key');
        $method = $target->mfaMethods()->sole();

        self::assertNull($method->disabled_at);
        self::assertNull($method->confirmed_at);
        self::assertNotSame($oldSecret, $method->secret);
        $response->assertSee($method->secret);

        $this->post('/login/mfa/enroll', [
            'code' => TOTP::createFromSecret($method->secret)->now(),
        ])->assertOk();
        $this->post('/login/mfa/recovery-codes', ['acknowledged' => '1'])->assertRedirect('/');
        $this->assertAuthenticatedAs($target);
        self::assertNotNull($method->refresh()->confirmed_at);
    }

    public function test_recovery_regeneration_requires_fresh_mfa_and_invalidates_every_old_code(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $method = $user->mfaMethods()->sole();
        UserRecoveryCode::query()->create([
            'user_mfa_method_id' => $method->id,
            'code_hmac' => str_repeat('d', 64),
        ]);
        $this->freshSessionFor($user);
        Queue::fake([SendQueuedNotifications::class]);

        $codes = $this->app->make(RegenerateRecoveryCodes::class)->handle($user, null, null, null);

        self::assertCount((int) config('identity.totp.recovery_code_count'), $codes);
        self::assertSame(count($codes), UserRecoveryCode::query()->count());
        self::assertFalse(UserRecoveryCode::query()->where('code_hmac', str_repeat('d', 64))->exists());
        self::assertTrue($this->app->make(RecoveryCodeHasher::class)->verify(
            $codes[0],
            $method->id,
            UserRecoveryCode::query()->oldest('id')->value('code_hmac'),
        ));
        Queue::assertPushed(SendQueuedNotifications::class, static fn (SendQueuedNotifications $job): bool => $job->notification instanceof RecoveryCodesRegeneratedNotification);
    }

    public function test_totp_rotation_requires_fresh_mfa_and_returns_a_new_encrypted_setup_once(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $method = $user->mfaMethods()->sole();
        $oldSecret = $method->secret;
        $this->freshSessionFor($user);

        $rotation = $this->app->make(RotateTotp::class)->handle($user, null, null, null);

        self::assertNotSame($oldSecret, $rotation['secret']);
        self::assertStringContainsString('<svg', $rotation['svg']);
        self::assertNotSame($rotation['secret'], $method->refresh()->getRawOriginal('secret'));
        self::assertNull($method->confirmed_at);
        self::assertNotNull($method->rotated_at);
        self::assertSame(2, $user->refresh()->session_version);
    }

    #[DataProvider('staleSessionStates')]
    public function test_credential_mutations_reject_incomplete_or_stale_authentication_sessions(
        string $action,
        string $state,
    ): void {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $authSession = $this->freshSessionFor($user);

        match ($state) {
            'inactive-user' => $user->update(['state' => UserState::Suspended]),
            'stale-version' => $user->increment('session_version'),
            'revoked' => $authSession->update(['revoked_at' => now()]),
            'missing-mfa' => $authSession->update(['mfa_authenticated_at' => null]),
            'stale-reauth' => $authSession->update([
                'reauthenticated_at' => now()->subMinutes((int) config('identity.privileged_reauth_minutes'))->subSecond(),
            ]),
            'inactive-session' => $authSession->update([
                'last_seen_at' => now()->subMinutes((int) config('identity.session.inactivity_minutes'))->subSecond(),
            ]),
            'absolute-expiry' => $authSession->update(['absolute_expires_at' => now()]),
        };

        $this->expectException(DomainRuleViolation::class);

        match ($action) {
            'regenerate' => $this->app->make(RegenerateRecoveryCodes::class)->handle($user, null, null, null),
            'rotate' => $this->app->make(RotateTotp::class)->handle($user, null, null, null),
        };
    }

    /** @return array<string, array{string, string}> */
    public static function staleSessionStates(): array
    {
        $states = [
            'inactive-user',
            'stale-version',
            'revoked',
            'missing-mfa',
            'stale-reauth',
            'inactive-session',
            'absolute-expiry',
        ];
        $cases = [];

        foreach (['regenerate', 'rotate'] as $action) {
            foreach ($states as $state) {
                $cases[$action.' '.$state] = [$action, $state];
            }
        }

        return $cases;
    }

    private function freshSessionFor(User $user): AuthSession
    {
        $sessionId = bin2hex(random_bytes(20));
        $session = $this->app->make(Session::class);
        $session->start();
        $session->setId($sessionId);

        return AuthSession::query()->create([
            'session_id' => $sessionId,
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'mfa_authenticated_at' => now(),
            'reauthenticated_at' => now(),
            'user_session_version' => $user->session_version,
        ]);
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
}
