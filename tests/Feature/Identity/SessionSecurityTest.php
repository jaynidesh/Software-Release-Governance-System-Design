<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Domain\Identity\Enums\UserState;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Support\Exceptions\AuthenticatedSessionPersistenceException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\TestCase;

final class SessionSecurityTest extends TestCase
{
    use RefreshDatabase;

    public function test_ordinary_login_creates_metadata_for_the_regenerated_session_before_response_completion(): void
    {
        $user = User::factory()->active()->create();
        $oldSessionId = $this->sessionStore()->getId();

        $this->post('/login/otp', ['email' => $user->email]);
        AuthChallenge::query()->sole()->update(['delivered_at' => now()]);
        $this->post('/login/verify', ['code' => $this->queuedOtpCode()])->assertRedirect('/');

        $session = AuthSession::query()->sole();
        self::assertNotSame($oldSessionId, $session->session_id);
        self::assertSame($this->sessionStore()->getId(), $session->session_id);
        self::assertSame($user->id, $session->user_id);
        self::assertNull($session->mfa_authenticated_at);
        self::assertNull($session->reauthenticated_at);
        self::assertSame($user->session_version, $session->user_session_version);
        self::assertTrue(DB::table('sessions')->where('id', $session->session_id)->exists());
    }

    public function test_metadata_write_failure_rolls_back_authentication_and_leaves_no_metadata(): void
    {
        $user = User::factory()->active()->create();
        $this->post('/login/otp', ['email' => $user->email]);
        AuthChallenge::query()->sole()->update(['delivered_at' => now()]);
        $dispatcher = AuthSession::getEventDispatcher();
        self::assertNotNull($dispatcher);
        AuthSession::setEventDispatcher(clone $dispatcher);
        AuthSession::creating(static function (): never {
            throw new RuntimeException('Synthetic metadata failure.');
        });

        try {
            $this->withoutExceptionHandling();
            $this->post('/login/verify', ['code' => $this->queuedOtpCode()]);
            self::fail('The synthetic metadata failure was not raised.');
        } catch (AuthenticatedSessionPersistenceException $exception) {
            self::assertSame('The authenticated session could not be persisted.', $exception->getMessage());
        } finally {
            AuthSession::setEventDispatcher($dispatcher);
        }

        $this->assertGuest();
        self::assertSame(0, AuthSession::query()->count());
        self::assertFalse(DB::table('sessions')->where('user_id', $user->id)->exists());
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.session.persistence_failed']);
    }

    #[DataProvider('invalidSessionStates')]
    public function test_invalid_authenticated_sessions_are_destroyed_with_a_generic_event_and_redirect(string $state): void
    {
        $user = User::factory()->active()->create();
        $authSession = $this->authenticate($user);
        $oldToken = $this->sessionStore()->token();

        match ($state) {
            'inactivity' => $authSession->update(['last_seen_at' => now()->subMinutes(16)]),
            'absolute' => $authSession->update(['absolute_expires_at' => now()]),
            'revoked' => $authSession->update(['revoked_at' => now()]),
            'version' => $user->increment('session_version'),
            'suspended' => $user->update(['state' => UserState::Suspended]),
            'deactivated' => $user->update(['state' => UserState::Deactivated]),
        };

        $this->get('/')->assertRedirect('/login')->assertSessionHas('status', 'Your session is no longer available. Please sign in again.');

        $this->assertGuest();
        self::assertNotSame($oldToken, $this->sessionStore()->token());
        self::assertFalse(AuthSession::query()->whereKey($authSession->id)->exists());
        self::assertFalse(DB::table('sessions')->where('id', $authSession->session_id)->exists());
        $event = SecurityEvent::query()->where('event_code', 'identity.session.invalidated')->sole();
        self::assertSame([], $event->metadata);
    }

    /** @return array<string, array{string}> */
    public static function invalidSessionStates(): array
    {
        return [
            'inactivity expiry' => ['inactivity'],
            'absolute expiry' => ['absolute'],
            'revocation' => ['revoked'],
            'session version' => ['version'],
            'suspended user' => ['suspended'],
            'deactivated user' => ['deactivated'],
        ];
    }

    public function test_absent_metadata_is_inert_and_clears_an_authenticated_payload(): void
    {
        $user = User::factory()->active()->create();
        $this->actingAs($user);

        $this->get('/')->assertRedirect('/login');

        $this->assertGuest();
        self::assertSame(0, AuthSession::query()->count());
    }

    public function test_activity_writes_are_bounded_and_prefetch_or_health_requests_do_not_extend_inactivity(): void
    {
        $this->travelTo('2026-09-23 10:00:00');
        $user = User::factory()->active()->create();
        $authSession = $this->authenticate($user, now()->subMinutes(2));

        $this->get('/')->assertOk();
        $firstSeen = $authSession->refresh()->last_seen_at;
        self::assertTrue($firstSeen?->equalTo(now()));

        $this->travel(30)->seconds();
        $this->get('/')->assertOk();
        self::assertTrue($authSession->refresh()->last_seen_at?->equalTo($firstSeen));

        $this->travel(31)->seconds();
        $this->withHeader('Purpose', 'prefetch')->get('/')->assertOk();
        self::assertTrue($authSession->refresh()->last_seen_at?->equalTo($firstSeen));

        $this->get('/health')->assertOk();
        self::assertTrue($authSession->refresh()->last_seen_at?->equalTo($firstSeen));
    }

    public function test_raw_session_id_is_hidden_from_model_serialization(): void
    {
        $user = User::factory()->active()->create();
        $authSession = $this->authenticate($user);

        self::assertArrayNotHasKey('session_id', $authSession->toArray());
        self::assertStringNotContainsString($authSession->session_id, $authSession->toJson());
    }

    private function authenticate(User $user, mixed $lastSeenAt = null): AuthSession
    {
        $session = $this->sessionStore();
        $session->start();
        $session->setId(bin2hex(random_bytes(20)));
        $this->actingAs($user);
        $this->withCookie((string) config('session.cookie'), $session->getId());

        return AuthSession::query()->create([
            'session_id' => $session->getId(),
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => $lastSeenAt ?? now(),
            'absolute_expires_at' => now()->addHours(8),
            'primary_authenticated_at' => now(),
            'user_session_version' => $user->session_version,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Test Browser',
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

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }
}
