<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Contracts\Identity\OtpDelivery;
use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\User;
use App\Notifications\Identity\EmailOtpNotification;
use App\Services\Identity\EmailOtpAuthenticationProvider;
use App\Services\Identity\LaravelOtpDelivery;
use App\Services\Identity\OtpHasher;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class EmailOtpAuthenticationTest extends TestCase
{
    use DatabaseMigrations;

    public function test_primary_provider_and_delivery_contracts_are_bound(): void
    {
        self::assertInstanceOf(
            EmailOtpAuthenticationProvider::class,
            $this->app->make(PrimaryAuthenticationProvider::class),
        );
        self::assertInstanceOf(LaravelOtpDelivery::class, $this->app->make(OtpDelivery::class));
    }

    public function test_login_form_is_focused_on_email_only(): void
    {
        $this->withoutVite();

        $this->get('/login')
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSee('Email address')
            ->assertDontSee('Password');
    }

    #[DataProvider('ineligibleIdentityStates')]
    public function test_begin_response_is_generic_for_every_ineligible_identity(string $state): void
    {
        Queue::fake([SendQueuedNotifications::class]);
        $email = 'person@example.test';
        $this->createIneligibleIdentity($state, $email);

        $response = $this->post('/login/otp', ['email' => ' PERSON@EXAMPLE.TEST ']);

        $response->assertRedirect('/login/verify')
            ->assertSessionHas('status', 'If the account is eligible, a sign-in code will be sent.')
            ->assertSessionHas('identity.auth_challenge')
            ->assertSessionHas('identity.auth_purpose', AuthenticationPurpose::Login->value)
            ->assertSessionHas('identity.otp_resend_available_at')
            ->assertHeader('Cache-Control', 'no-store, private');
        self::assertSame(0, AuthChallenge::query()->count());
        Queue::assertNothingPushed();
    }

    /** @return array<string, array{string}> */
    public static function ineligibleIdentityStates(): array
    {
        return [
            'unknown' => ['unknown'],
            'expired invitation' => ['expired-invitation'],
            'suspended' => ['suspended'],
            'deactivated' => ['deactivated'],
            'locked' => ['locked'],
        ];
    }

    public function test_eligible_request_persists_only_a_bound_hmac_and_queues_encrypted_delivery(): void
    {
        $user = User::factory()->active()->create(['email' => 'person@example.test']);

        $response = $this->post('/login/otp', ['email' => 'PERSON@example.test']);

        $response->assertRedirect('/login/verify')
            ->assertSessionHas('identity.auth_challenge')
            ->assertSessionHas('identity.auth_purpose', AuthenticationPurpose::Login->value)
            ->assertSessionMissing('email')
            ->assertSessionMissing('otp')
            ->assertSessionMissing('code');
        $challenge = AuthChallenge::query()->sole();
        self::assertSame($user->id, $challenge->user_id);
        self::assertSame(64, mb_strlen($challenge->code_hmac));
        self::assertNull($challenge->delivered_at);

        $payloadJson = (string) DB::table('jobs')->sole()->payload;
        /** @var array{queue: string, data: array{command: string}} $payload */
        $payload = json_decode($payloadJson, true, flags: JSON_THROW_ON_ERROR);
        $serialized = $this->app->make(Encrypter::class)->decrypt($payload['data']['command']);
        self::assertIsString($serialized);
        $job = unserialize($serialized, ['allowed_classes' => true]);
        self::assertInstanceOf(SendQueuedNotifications::class, $job);
        self::assertTrue($job->shouldBeEncrypted);
        self::assertSame('security', $job->queue);
        self::assertInstanceOf(EmailOtpNotification::class, $job->notification);
        self::assertStringNotContainsString($job->notification->code, $payloadJson);
        self::assertStringNotContainsString($job->notification->code, $challenge->toJson());
        self::assertTrue($this->app->make(OtpHasher::class)->verify(
            $job->notification->code,
            $challenge->public_id,
            $user->id,
            AuthenticationPurpose::Login,
            $challenge->code_hmac,
        ));
    }

    public function test_delivery_is_dispatched_only_after_the_transaction_commits(): void
    {
        $user = User::factory()->active()->create();
        $challenge = $this->createChallenge($user);
        $delivery = $this->app->make(OtpDelivery::class);

        DB::beginTransaction();
        $delivery->deliver($user, $challenge, '123456');
        self::assertSame(0, DB::table('jobs')->count());
        DB::commit();

        $job = $this->queuedNotification();
        self::assertSame('security', $job->queue);
        self::assertTrue($job->shouldBeEncrypted);
        self::assertInstanceOf(EmailOtpNotification::class, $job->notification);
        self::assertSame('123456', $job->notification->code);
    }

    public function test_email_notification_reuses_the_original_code_and_contains_no_login_token(): void
    {
        $user = User::factory()->active()->make(['email' => 'person@example.test']);
        $notification = new EmailOtpNotification('01K5CHALLENGE0000000000000', '123456');

        $message = $notification->toMail($user)->toArray();

        self::assertContains('123456', $message['introLines']);
        self::assertStringNotContainsString('01K5CHALLENGE0000000000000', implode(' ', $message['introLines']));
        self::assertInstanceOf(ShouldQueue::class, $notification);
        self::assertInstanceOf(ShouldBeEncrypted::class, $notification);
    }

    public function test_delivery_retry_rechecks_challenge_state_and_marks_only_actual_delivery(): void
    {
        $user = User::factory()->active()->create();
        $reference = strtolower((string) Str::ulid());
        $challenge = new AuthChallenge([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'code_hmac' => $this->app->make(OtpHasher::class)->hash(
                '123456',
                $reference,
                $user->id,
                AuthenticationPurpose::Login,
            ),
            'expires_at' => now()->addMinutes(10),
        ]);
        $challenge->public_id = $reference;
        $challenge->save();
        $notification = new EmailOtpNotification($reference, '123456');

        self::assertTrue($notification->shouldSend($user, 'mail'));
        self::assertNull($challenge->refresh()->delivered_at);
        $notification->afterSending($user, 'mail', null);
        self::assertNotNull($challenge->refresh()->delivered_at);

        $challenge->update(['invalidated_at' => now()]);
        self::assertFalse($notification->shouldSend($user, 'mail'));
    }

    public function test_resend_wait_reuses_the_open_challenge_then_replaces_it_after_the_wait(): void
    {
        $this->travelTo('2026-09-22 10:00:00');
        Queue::fake([SendQueuedNotifications::class]);
        User::factory()->active()->create(['email' => 'person@example.test']);

        $this->post('/login/otp', ['email' => 'person@example.test']);
        $firstChallenge = AuthChallenge::query()->sole();
        $this->travel(30)->seconds();
        $this->post('/login/otp', ['email' => 'person@example.test']);

        self::assertSame(1, AuthChallenge::query()->count());
        self::assertNull($firstChallenge->refresh()->invalidated_at);
        Queue::assertPushed(SendQueuedNotifications::class, 1);

        $this->travel(31)->seconds();
        $this->post('/login/otp', ['email' => 'person@example.test']);

        self::assertSame(2, AuthChallenge::query()->count());
        self::assertNotNull($firstChallenge->refresh()->invalidated_at);
        Queue::assertPushed(SendQueuedNotifications::class, 2);
    }

    public function test_verification_screen_offers_an_accessible_server_timed_resend_without_storing_email(): void
    {
        $this->travelTo('2026-09-29 10:00:00');
        $this->withoutVite();
        Queue::fake([SendQueuedNotifications::class]);
        User::factory()->active()->create(['email' => 'person@example.test']);

        $this->post('/login/otp', ['email' => 'person@example.test']);

        $this->get('/login/verify')
            ->assertOk()
            ->assertViewHas('resendAvailableAt', now()->addSeconds(60))
            ->assertSee('Request another code')
            ->assertSee('data-otp-resend', false)
            ->assertSee('aria-live="polite"', false)
            ->assertSee('disabled', false);
        self::assertFalse(session()->has('email'));
    }

    public function test_resend_action_preserves_the_challenge_during_the_delay_and_replaces_it_afterward(): void
    {
        $this->travelTo('2026-09-29 10:00:00');
        Queue::fake([SendQueuedNotifications::class]);
        User::factory()->active()->create(['email' => 'person@example.test']);
        $this->post('/login/otp', ['email' => 'person@example.test']);
        $firstChallenge = AuthChallenge::query()->sole();

        $this->travel(30)->seconds();
        $this->post('/login/resend')
            ->assertRedirect('/login/verify')
            ->assertSessionHas('status', 'If the account remains eligible, a new code may have been sent.');
        self::assertSame($firstChallenge->public_id, session('identity.auth_challenge'));
        self::assertSame(1, AuthChallenge::query()->count());
        Queue::assertPushed(SendQueuedNotifications::class, 1);

        $this->travel(31)->seconds();
        $this->post('/login/resend')
            ->assertRedirect('/login/verify')
            ->assertSessionHas('status', 'If the account remains eligible, a new code may have been sent.');
        self::assertNotSame($firstChallenge->public_id, session('identity.auth_challenge'));
        self::assertSame(2, AuthChallenge::query()->count());
        Queue::assertPushed(SendQueuedNotifications::class, 2);
    }

    public function test_verify_page_is_indistinguishable_for_eligible_unknown_ineligible_and_throttled_requests(): void
    {
        $this->travelTo('2026-09-30 10:00:00');
        $this->withoutVite();
        Queue::fake([SendQueuedNotifications::class]);
        User::factory()->active()->create(['email' => 'eligible@example.test']);
        User::factory()->suspended()->create(['email' => 'suspended@example.test']);

        $eligible = $this->beginAndView('eligible@example.test');
        $unknown = $this->beginAndView('unknown@example.test');
        $ineligible = $this->beginAndView('suspended@example.test');
        config()->set('identity.otp.request_limit', 1);
        $throttled = $this->beginAndView('eligible@example.test');

        foreach ([$unknown, $ineligible, $throttled] as $attempt) {
            self::assertSame($eligible['redirect'], $attempt['redirect']);
            self::assertSame($eligible['redirect_cache_control'], $attempt['redirect_cache_control']);
            self::assertSame($eligible['content'], $attempt['content']);
            self::assertSame($eligible['cache_control'], $attempt['cache_control']);
            self::assertSame(array_keys($eligible['state']), array_keys($attempt['state']));
            self::assertSame(
                $eligible['state']['identity.otp_resend_available_at'],
                $attempt['state']['identity.otp_resend_available_at'],
            );
            self::assertIsString($attempt['state']['identity.auth_challenge']);
            self::assertIsString($attempt['state']['identity.auth_purpose']);
        }
    }

    public function test_resend_after_delay_is_indistinguishable_for_eligible_unknown_ineligible_and_throttled_requests(): void
    {
        $this->withoutVite();
        Queue::fake([SendQueuedNotifications::class]);
        User::factory()->active()->create(['email' => 'eligible-resend@example.test']);
        User::factory()->active()->create(['email' => 'throttled-resend@example.test']);
        User::factory()->suspended()->create(['email' => 'suspended-resend@example.test']);

        $eligible = $this->resendAfterDelay('eligible-resend@example.test', false);
        $unknown = $this->resendAfterDelay('unknown-resend@example.test', false);
        $ineligible = $this->resendAfterDelay('suspended-resend@example.test', false);
        $throttled = $this->resendAfterDelay('throttled-resend@example.test', true);

        foreach ([$unknown, $ineligible, $throttled] as $attempt) {
            self::assertSame($eligible['redirect'], $attempt['redirect']);
            self::assertSame($eligible['redirect_cache_control'], $attempt['redirect_cache_control']);
            self::assertSame($eligible['status'], $attempt['status']);
            self::assertSame($eligible['content'], $attempt['content']);
            self::assertSame($eligible['cache_control'], $attempt['cache_control']);
            self::assertSame(
                $eligible['state']['identity.otp_resend_available_at'],
                $attempt['state']['identity.otp_resend_available_at'],
            );
            self::assertSame(array_keys($eligible['state']), array_keys($attempt['state']));
        }
    }

    public function test_identifier_and_ip_request_limits_are_independent(): void
    {
        config()->set('identity.otp.request_limit', 2);
        config()->set('identity.otp.ip_request_limit', 3);
        Queue::fake([SendQueuedNotifications::class]);
        User::factory()->count(4)->sequence(
            ['email' => 'one@example.test'],
            ['email' => 'two@example.test'],
            ['email' => 'three@example.test'],
            ['email' => 'four@example.test'],
        )->active()->create();

        $this->post('/login/otp', ['email' => 'one@example.test']);
        $this->post('/login/otp', ['email' => 'one@example.test']);
        $this->post('/login/otp', ['email' => 'one@example.test']);
        self::assertSame(1, AuthChallenge::query()->count());

        $this->post('/login/otp', ['email' => 'two@example.test']);
        $this->post('/login/otp', ['email' => 'three@example.test']);
        $this->post('/login/otp', ['email' => 'four@example.test']);

        self::assertSame(1, AuthChallenge::query()->count());
    }

    private function createIneligibleIdentity(string $state, string $email): void
    {
        match ($state) {
            'unknown' => null,
            'expired-invitation' => User::factory()->invited()->create([
                'email' => $email,
                'invitation_expires_at' => now()->subSecond(),
            ]),
            'suspended' => User::factory()->suspended()->create(['email' => $email]),
            'deactivated' => User::factory()->deactivated()->create(['email' => $email]),
            'locked' => User::factory()->locked()->create(['email' => $email]),
        };
    }

    /** @return array{redirect: array{int, ?string}, redirect_cache_control: ?string, content: string, cache_control: ?string, state: array<string, mixed>} */
    private function beginAndView(string $email): array
    {
        $response = $this->post('/login/otp', ['email' => $email]);
        $view = $this->get('/login/verify');

        return [
            'redirect' => [$response->getStatusCode(), $response->headers->get('Location')],
            'redirect_cache_control' => $response->headers->get('Cache-Control'),
            'content' => (string) $view->getContent(),
            'cache_control' => $view->headers->get('Cache-Control'),
            'state' => $this->authenticationPresentationState(),
        ];
    }

    /** @return array{redirect: array{int, ?string}, redirect_cache_control: ?string, status: mixed, content: string, cache_control: ?string, state: array<string, mixed>} */
    private function resendAfterDelay(string $email, bool $throttled): array
    {
        $this->travelTo('2026-09-30 12:00:00');
        config()->set('identity.otp.request_limit', $throttled ? 1 : 10);
        $this->post('/login/otp', ['email' => $email]);
        $this->travel(61)->seconds();
        $response = $this->post('/login/resend');
        $view = $this->get('/login/verify');

        return [
            'redirect' => [$response->getStatusCode(), $response->headers->get('Location')],
            'redirect_cache_control' => $response->headers->get('Cache-Control'),
            'status' => session('status'),
            'content' => (string) $view->getContent(),
            'cache_control' => $view->headers->get('Cache-Control'),
            'state' => $this->authenticationPresentationState(),
        ];
    }

    /** @return array<string, mixed> */
    private function authenticationPresentationState(): array
    {
        self::assertFalse(session()->has('email'));
        self::assertFalse(session()->has('otp'));
        self::assertFalse(session()->has('code'));

        return [
            'identity.auth_challenge' => session('identity.auth_challenge'),
            'identity.auth_purpose' => session('identity.auth_purpose'),
            'identity.otp_resend_available_at' => session('identity.otp_resend_available_at'),
        ];
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
