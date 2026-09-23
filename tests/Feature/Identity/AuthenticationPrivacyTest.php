<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Users\CreateInvitedUser;
use App\Application\Identity\Users\ResendInvitation;
use App\Application\Identity\Users\RevokeInvitation;
use App\Application\Identity\Users\UnlockUser;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\AuthChallenge;
use App\Models\LoginEvent;
use App\Models\PendingAuthentication;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Notifications\Identity\AccountUnlockedNotification;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Notifications\Identity\EmailOtpNotification;
use App\Notifications\Identity\InvitationRevokedNotification;
use App\Services\Identity\OtpHasher;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Foundation\Application as ApplicationContract;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Notifications\Events\NotificationFailed;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Mockery;
use Monolog\Handler\TestHandler;
use RuntimeException;
use Tests\TestCase;

final class AuthenticationPrivacyTest extends TestCase
{
    use DatabaseMigrations;

    public function test_invited_user_creation_commits_before_encrypted_invitation_delivery(): void
    {
        $this->allowAdministration();
        $actor = User::factory()->active()->create();
        $action = $this->app->make(CreateInvitedUser::class);

        DB::beginTransaction();
        $user = $action->handle($actor, [
            'employee_number' => 'EMP-42',
            'name' => 'Invited Person',
            'email' => ' PERSON@EXAMPLE.TEST ',
            'timezone' => 'Indian/Mauritius',
        ], '127.0.0.1', 'Test Agent', 'corr-create');
        self::assertSame(0, DB::table('jobs')->count());
        DB::commit();

        $user->refresh();
        self::assertSame('person@example.test', $user->email);
        self::assertSame(UserState::Invited, $user->state);
        self::assertNotNull($user->invited_at);
        self::assertNotNull($user->invitation_expires_at);
        $job = $this->queuedNotification();
        self::assertSame('security', $job->queue);
        self::assertTrue($job->shouldBeEncrypted);
        self::assertInstanceOf(ActivationInvitationNotification::class, $job->notification);
        self::assertInstanceOf(ShouldBeEncrypted::class, $job->notification);
        $mail = $job->notification->toMail($user)->toArray();
        self::assertStringContainsString('/login', (string) $mail['actionUrl']);
        self::assertStringNotContainsString('token', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
        self::assertStringNotContainsString('code', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
        $this->assertDatabaseHas('security_events', [
            'actor_id' => $actor->id,
            'subject_user_id' => $user->id,
            'event_code' => 'identity.invitation.created',
            'correlation_id' => 'corr-create',
        ]);
    }

    public function test_invitation_resend_invalidates_open_authentication_state_and_renews_expiry(): void
    {
        $this->allowAdministration();
        $actor = User::factory()->active()->create();
        $user = User::factory()->invited()->create(['invitation_expires_at' => now()->subDay()]);
        $challenge = $this->challengeFor($user, AuthenticationPurpose::Activation);
        $pending = PendingAuthentication::query()->create([
            'user_id' => $user->id,
            'auth_challenge_id' => $challenge->id,
            'purpose' => AuthenticationPurpose::Activation,
            'session_id_hmac' => str_repeat('b', 64),
            'user_session_version' => $user->session_version,
            'expires_at' => now()->addMinutes(10),
        ]);

        $this->app->make(ResendInvitation::class)->handle(
            $actor,
            $user,
            '127.0.0.1',
            'Test Agent',
            'corr-resend',
        );

        self::assertTrue($user->refresh()->invitation_expires_at?->isFuture());
        self::assertNotNull($challenge->refresh()->invalidated_at);
        self::assertNotNull($pending->refresh()->invalidated_at);
        self::assertSame(1, DB::table('jobs')->count());
        $this->assertDatabaseHas('security_events', [
            'event_code' => 'identity.invitation.resent',
            'correlation_id' => 'corr-resend',
        ]);
    }

    public function test_invitation_revoke_expires_eligibility_without_deleting_identity(): void
    {
        $this->allowAdministration();
        $actor = User::factory()->active()->create();
        $user = User::factory()->invited()->create();
        $challenge = $this->challengeFor($user, AuthenticationPurpose::Activation);

        $this->app->make(RevokeInvitation::class)->handle(
            $actor,
            $user,
            '127.0.0.1',
            'Test Agent',
            'corr-revoke',
        );

        self::assertTrue($user->refresh()->invitation_expires_at?->isPast());
        self::assertNotNull($challenge->refresh()->invalidated_at);
        self::assertSame(UserState::Invited, $user->state);
        $this->assertDatabaseHas('security_events', [
            'event_code' => 'identity.invitation.revoked',
            'correlation_id' => 'corr-revoke',
        ]);
    }

    public function test_administrator_unlock_clears_failures_invalidates_state_and_increments_session_version(): void
    {
        $this->allowAdministration();
        $actor = User::factory()->active()->create();
        $user = User::factory()->locked()->create();
        $originalVersion = $user->session_version;
        $challenge = $this->challengeFor($user, AuthenticationPurpose::Login);

        $this->app->make(UnlockUser::class)->handle(
            $actor,
            $user,
            '127.0.0.1',
            'Test Agent',
            'corr-unlock',
        );

        $user->refresh();
        self::assertSame(0, $user->failed_auth_attempts);
        self::assertNull($user->failed_auth_window_started_at);
        self::assertNull($user->locked_until);
        self::assertSame($originalVersion + 1, $user->session_version);
        self::assertNotNull($challenge->refresh()->invalidated_at);
        $this->assertDatabaseHas('security_events', [
            'event_code' => 'identity.account.unlocked',
            'correlation_id' => 'corr-unlock',
        ]);
    }

    public function test_pending_authentication_can_only_be_cancelled_by_post_and_rotates_the_session(): void
    {
        $this->get('/login/pending/cancel')->assertMethodNotAllowed();
        $user = User::factory()->privileged()->create();
        $reference = strtolower((string) Str::ulid());
        $challenge = new AuthChallenge([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'expires_at' => now()->addMinutes(10),
            'delivered_at' => now(),
        ]);
        $challenge->public_id = $reference;
        $challenge->code_hmac = $this->app->make(OtpHasher::class)->hash(
            '123456',
            $reference,
            $user->id,
            AuthenticationPurpose::Login,
        );
        $challenge->save();
        $this->withSession([
            'identity.auth_challenge' => $challenge->public_id,
            'identity.auth_purpose' => AuthenticationPurpose::Login->value,
        ])->post('/login/verify', ['code' => '123456'])->assertSessionHas('identity.pending_authentication');
        $pending = PendingAuthentication::query()->sole();
        $oldSessionId = session()->getId();
        $this->withCookie((string) config('session.cookie'), $oldSessionId);

        $this->post('/login/pending/cancel')->assertRedirect('/login');

        self::assertNotNull($pending->refresh()->invalidated_at);
        self::assertFalse(session()->has('identity.pending_authentication'));
        self::assertNotSame($oldSessionId, session()->getId());
        $this->assertGuest();
    }

    public function test_authentication_mutations_reject_missing_csrf_and_forbidden_legacy_routes_do_not_exist(): void
    {
        $this->app->bind(
            PreventRequestForgery::class,
            static fn (ApplicationContract $app): PreventRequestForgery => new class($app, $app->make(Encrypter::class)) extends PreventRequestForgery
            {
                protected function runningUnitTests(): bool
                {
                    return false;
                }
            },
        );

        $this->post('/login/otp', ['email' => 'person@example.test'])->assertStatus(419);
        $this->get('/register')->assertNotFound();
        $this->get('/forgot-password')->assertNotFound();
        $this->get('/reset-password')->assertNotFound();
        $this->get('/logout')->assertNotFound();
        self::assertSame(0, AuthChallenge::query()->count());
    }

    public function test_malformed_or_absent_verification_state_uses_the_same_generic_error(): void
    {
        $this->post('/login/verify', ['code' => 'abc'])
            ->assertRedirect('/login/verify')
            ->assertSessionHasErrors(['code' => 'The code is invalid or expired.']);

        $this->post('/login/verify', ['code' => '123456'])
            ->assertRedirect('/login/verify')
            ->assertSessionHasErrors(['code' => 'The code is invalid or expired.']);
    }

    public function test_malformed_otp_is_never_flashed_and_validation_response_is_not_cacheable(): void
    {
        $plaintext = '91827X';

        $response = $this->post('/login/verify', ['code' => ' '.$plaintext.' ']);

        $response->assertRedirect('/login/verify')
            ->assertSessionHasErrors(['code' => 'The code is invalid or expired.']);
        $oldInput = session('_old_input', []);
        self::assertIsArray($oldInput);
        self::assertArrayNotHasKey('code', $oldInput);
        $response->assertHeader('Cache-Control', 'no-store, private');
        self::assertStringNotContainsString($plaintext, json_encode(session()->all(), JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString($plaintext, (string) $response->getContent());
        self::assertStringNotContainsString($plaintext, $this->serializedAuthenticationStorage());
    }

    public function test_eligible_enqueue_failure_keeps_generic_response_and_records_only_safe_context(): void
    {
        $email = 'enqueue-failure@example.test';
        User::factory()->active()->create(['email' => $email]);
        $capturedCode = null;
        $bus = Mockery::mock(BusDispatcher::class);
        $bus->shouldReceive('dispatch')->once()->andReturnUsing(
            function (SendQueuedNotifications $job) use (&$capturedCode, $email): never {
                self::assertInstanceOf(EmailOtpNotification::class, $job->notification);
                $capturedCode = $job->notification->code;

                throw new RuntimeException('Cannot enqueue '.$email.' with OTP '.$capturedCode);
            },
        );
        $this->app->instance(BusDispatcher::class, $bus);
        $handler = new TestHandler;
        Log::getLogger()->pushHandler($handler);

        $unknownResponse = $this->post('/login/otp', ['email' => 'unknown-enqueue@example.test']);
        $eligibleResponse = $this->post('/login/otp', ['email' => $email]);

        $unknownResponse->assertRedirect('/login/verify')
            ->assertSessionHas('status', 'If the account is eligible, a sign-in code will be sent.');
        $eligibleResponse->assertRedirect('/login/verify')
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSessionHas('status', 'If the account is eligible, a sign-in code will be sent.');
        self::assertSame($unknownResponse->getStatusCode(), $eligibleResponse->getStatusCode());
        self::assertSame($unknownResponse->headers->get('Location'), $eligibleResponse->headers->get('Location'));
        self::assertIsString($capturedCode);
        self::assertMatchesRegularExpression('/^\d{6}$/', $capturedCode);
        self::assertStringNotContainsString($capturedCode, json_encode(session()->all(), JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString($email, json_encode(session()->all(), JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString($email, json_encode($handler->getRecords(), JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString($capturedCode, json_encode($handler->getRecords(), JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString($capturedCode, $this->serializedAuthenticationStorage());
        self::assertStringNotContainsString($email, $this->serializedAuthenticationStorage());
        self::assertStringNotContainsString($capturedCode, (string) $eligibleResponse->getContent());
        self::assertStringNotContainsString($email, (string) $eligibleResponse->getContent());
        $challenge = AuthChallenge::query()->sole();
        $this->assertDatabaseHas('security_events', [
            'subject_user_id' => $challenge->user_id,
            'event_code' => 'identity.otp.delivery_failed',
            'correlation_id' => $challenge->correlation_id,
        ]);
    }

    public function test_invitation_revocation_notice_is_encrypted_after_commit_and_discarded_on_rollback(): void
    {
        $this->allowAdministration();
        $actor = User::factory()->active()->create();
        $user = User::factory()->invited()->create();
        $action = $this->app->make(RevokeInvitation::class);

        DB::beginTransaction();
        $action->handle($actor, $user, '127.0.0.1', 'Test Agent', 'corr-revoke-rollback');
        self::assertSame(0, DB::table('jobs')->count());
        DB::rollBack();
        self::assertSame(0, DB::table('jobs')->count());

        DB::beginTransaction();
        $action->handle($actor, $user->refresh(), '127.0.0.1', 'Test Agent', 'corr-revoke-commit');
        self::assertSame(0, DB::table('jobs')->count());
        DB::commit();

        $job = $this->queuedNotification();
        self::assertSame('security', $job->queue);
        self::assertTrue($job->shouldBeEncrypted);
        self::assertInstanceOf(InvitationRevokedNotification::class, $job->notification);
        $mail = $job->notification->toMail($user)->toArray();
        self::assertStringContainsString('revoked', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
        self::assertStringNotContainsString('token', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
        self::assertStringNotContainsString('code', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
    }

    public function test_unlock_notice_is_encrypted_after_commit_and_discarded_on_rollback(): void
    {
        $this->allowAdministration();
        $actor = User::factory()->active()->create();
        $user = User::factory()->locked()->create();
        $action = $this->app->make(UnlockUser::class);

        DB::beginTransaction();
        $action->handle($actor, $user, '127.0.0.1', 'Test Agent', 'corr-unlock-rollback');
        self::assertSame(0, DB::table('jobs')->count());
        DB::rollBack();
        self::assertSame(0, DB::table('jobs')->count());

        DB::beginTransaction();
        $action->handle($actor, $user->refresh(), '127.0.0.1', 'Test Agent', 'corr-unlock-commit');
        self::assertSame(0, DB::table('jobs')->count());
        DB::commit();

        $job = $this->queuedNotification();
        self::assertSame('security', $job->queue);
        self::assertTrue($job->shouldBeEncrypted);
        self::assertInstanceOf(AccountUnlockedNotification::class, $job->notification);
        $mail = $job->notification->toMail($user)->toArray();
        self::assertStringContainsString('unlocked', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
        self::assertStringNotContainsString('token', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
        self::assertStringNotContainsString('code', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
    }

    public function test_valid_verification_without_session_state_records_generic_authentication_failure(): void
    {
        $response = $this->post('/login/verify', ['code' => '123456']);
        $correlationId = $response->headers->get('X-Correlation-ID');

        $response->assertRedirect('/login/verify')
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSessionHasErrors(['code' => 'The code is invalid or expired.']);
        self::assertIsString($correlationId);
        $this->assertDatabaseHas('security_events', [
            'subject_user_id' => null,
            'event_code' => 'identity.authentication.failed',
            'correlation_id' => $correlationId,
        ]);
        self::assertStringNotContainsString('123456', SecurityEvent::query()->sole()->toJson());
    }

    public function test_unresolved_challenge_records_both_generic_verification_and_authentication_failures(): void
    {
        $response = $this->withSession([
            'identity.auth_challenge' => strtolower((string) Str::ulid()),
            'identity.auth_purpose' => AuthenticationPurpose::Login->value,
        ])->post('/login/verify', ['code' => '654321']);
        $correlationId = $response->headers->get('X-Correlation-ID');

        $response->assertRedirect('/login/verify')
            ->assertSessionHasErrors(['code' => 'The code is invalid or expired.']);
        self::assertIsString($correlationId);
        self::assertSame(1, SecurityEvent::query()
            ->where('event_code', 'identity.otp.verification_failed')
            ->where('correlation_id', $correlationId)
            ->count());
        self::assertSame(1, SecurityEvent::query()
            ->where('event_code', 'identity.authentication.failed')
            ->where('correlation_id', $correlationId)
            ->count());
        self::assertStringNotContainsString('654321', SecurityEvent::query()->get()->toJson());
    }

    public function test_delivery_failure_records_safe_event_and_log_context_without_the_code(): void
    {
        $user = User::factory()->active()->create();
        $challenge = $this->challengeFor($user, AuthenticationPurpose::Login);
        $challenge->update(['correlation_id' => 'corr-delivery']);
        $notification = new EmailOtpNotification(
            $challenge->public_id,
            '918273',
        );
        $handler = new TestHandler;
        Log::getLogger()->pushHandler($handler);

        Event::dispatch(new NotificationFailed(
            $user,
            $notification,
            'mail',
            ['exception' => new RuntimeException('Transport unavailable')],
        ));

        $this->assertDatabaseHas('security_events', [
            'subject_user_id' => $user->id,
            'event_code' => 'identity.otp.delivery_failed',
            'correlation_id' => 'corr-delivery',
        ]);
        self::assertTrue($handler->hasErrorRecords());
        $serializedRecords = json_encode($handler->getRecords(), JSON_THROW_ON_ERROR);
        self::assertStringContainsString($challenge->public_id, $serializedRecords);
        self::assertStringContainsString('corr-delivery', $serializedRecords);
        self::assertStringNotContainsString('918273', $serializedRecords);
    }

    private function allowAdministration(): void
    {
        $this->app->instance(AuthorizationService::class, new class implements AuthorizationService
        {
            public function allows(
                User $user,
                string $permission,
                ?Application $application,
                bool $requiresFreshReauthentication,
            ): bool {
                return $permission === 'admin.users' && $requiresFreshReauthentication;
            }
        });
    }

    private function challengeFor(User $user, AuthenticationPurpose $purpose): AuthChallenge
    {
        return AuthChallenge::query()->create([
            'user_id' => $user->id,
            'purpose' => $purpose,
            'code_hmac' => str_repeat('a', 64),
            'expires_at' => now()->addMinutes(10),
            'delivered_at' => now(),
        ]);
    }

    private function queuedNotification(): SendQueuedNotifications
    {
        /** @var array{data: array{command: string}} $payload */
        $payload = json_decode((string) DB::table('jobs')->sole()->payload, true, flags: JSON_THROW_ON_ERROR);
        $serialized = $this->app->make(Encrypter::class)->decrypt($payload['data']['command']);
        self::assertIsString($serialized);
        $job = unserialize($serialized, ['allowed_classes' => true]);
        self::assertInstanceOf(SendQueuedNotifications::class, $job);

        return $job;
    }

    private function serializedAuthenticationStorage(): string
    {
        return json_encode([
            'challenges' => AuthChallenge::query()->get()->toArray(),
            'login_events' => LoginEvent::query()->get()->toArray(),
            'security_events' => SecurityEvent::query()->get()->toArray(),
            'pending_authentications' => PendingAuthentication::query()->get()->toArray(),
            'jobs' => DB::table('jobs')->get()->toArray(),
            'sessions' => DB::table('sessions')->get()->toArray(),
        ], JSON_THROW_ON_ERROR);
    }
}
