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
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Notifications\Identity\EmailOtpNotification;
use App\Services\Identity\OtpHasher;
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
}
