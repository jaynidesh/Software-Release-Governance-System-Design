<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\PendingAuthentication;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Support\Exceptions\AuthenticatedSessionPersistenceException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use OTPHP\TOTP;
use RuntimeException;
use Tests\TestCase;

final class AuthSessionPersistenceTest extends TestCase
{
    use RefreshDatabase;

    public function test_privileged_login_persists_one_metadata_row_for_the_final_payload(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $pendingSessionId = $this->beginPrivilegedLogin($user);
        $method = $user->mfaMethods()->sole();

        $this->post('/login/mfa', ['code' => TOTP::createFromSecret($method->secret)->now()])
            ->assertRedirect('/');

        $authSession = AuthSession::query()->sole();
        self::assertSame($this->sessionStore()->getId(), $authSession->session_id);
        self::assertNotSame($pendingSessionId, $authSession->session_id);
        self::assertNotNull($authSession->mfa_authenticated_at);
        self::assertNotNull($authSession->reauthenticated_at);
        self::assertTrue(DB::table('sessions')->where('id', $authSession->session_id)->where('user_id', $user->id)->exists());
        self::assertFalse(DB::table('sessions')->where('id', $pendingSessionId)->exists());
    }

    public function test_reauthentication_rekeys_the_same_metadata_row_twice_and_deletes_both_old_payloads(): void
    {
        $user = User::factory()->active()->mfaConfirmed()->create();
        $authSession = $this->authenticate($user);
        $initialSessionId = $authSession->session_id;
        $this->post('/reauthenticate', ['return_route' => 'identity.security.index']);
        AuthChallenge::query()->sole()->update(['delivered_at' => now()]);
        $this->post('/reauthenticate/verify', ['code' => $this->queuedOtpCode()]);
        $primarySessionId = $authSession->refresh()->session_id;
        $this->withCookie((string) config('session.cookie'), $primarySessionId);

        $this->post('/reauthenticate/mfa', [
            'code' => TOTP::createFromSecret($user->mfaMethods()->sole()->secret)->now(),
        ])->assertRedirect('/security');

        $authSession->refresh();
        self::assertSame(1, AuthSession::query()->count());
        self::assertNotSame($initialSessionId, $primarySessionId);
        self::assertNotSame($primarySessionId, $authSession->session_id);
        self::assertFalse(DB::table('sessions')->whereIn('id', [$initialSessionId, $primarySessionId])->exists());
        self::assertTrue(DB::table('sessions')->where('id', $authSession->session_id)->exists());
    }

    public function test_privileged_login_metadata_failure_rolls_back_proof_and_authentication(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $this->beginPrivilegedLogin($user);
        $pending = PendingAuthentication::query()->sole();
        $dispatcher = AuthSession::getEventDispatcher();
        self::assertNotNull($dispatcher);
        AuthSession::setEventDispatcher(clone $dispatcher);
        AuthSession::creating(static function (): never {
            throw new RuntimeException('Synthetic privileged metadata failure.');
        });

        try {
            $this->withoutExceptionHandling();
            $this->post('/login/mfa', [
                'code' => TOTP::createFromSecret($user->mfaMethods()->sole()->secret)->now(),
            ]);
            self::fail('The synthetic privileged metadata failure was not raised.');
        } catch (AuthenticatedSessionPersistenceException $exception) {
            self::assertSame('The authenticated session could not be persisted.', $exception->getMessage());
        } finally {
            AuthSession::setEventDispatcher($dispatcher);
        }

        $this->assertGuest();
        self::assertNull($pending->refresh()->completed_at);
        self::assertSame(0, AuthSession::query()->count());
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.session.persistence_failed']);
    }

    public function test_reauthentication_metadata_failure_restores_the_prior_authenticated_session(): void
    {
        $user = User::factory()->active()->mfaConfirmed()->create();
        $authSession = $this->authenticate($user);
        $this->post('/reauthenticate', ['return_route' => 'identity.security.index']);
        AuthChallenge::query()->sole()->update(['delivered_at' => now()]);
        $this->post('/reauthenticate/verify', ['code' => $this->queuedOtpCode()]);
        $primarySessionId = $authSession->refresh()->session_id;
        $this->withCookie((string) config('session.cookie'), $primarySessionId);
        $pending = PendingAuthentication::query()->sole();
        $dispatcher = AuthSession::getEventDispatcher();
        self::assertNotNull($dispatcher);
        AuthSession::setEventDispatcher(clone $dispatcher);
        AuthSession::updating(static function (AuthSession $session): void {
            if ($session->isDirty('reauthenticated_at')) {
                throw new RuntimeException('Synthetic rekey metadata failure.');
            }
        });

        try {
            $this->withoutExceptionHandling();
            $this->post('/reauthenticate/mfa', [
                'code' => TOTP::createFromSecret($user->mfaMethods()->sole()->secret)->now(),
            ]);
            self::fail('The synthetic rekey metadata failure was not raised.');
        } catch (AuthenticatedSessionPersistenceException $exception) {
            self::assertSame('The authenticated session could not be persisted.', $exception->getMessage());
        } finally {
            AuthSession::setEventDispatcher($dispatcher);
        }

        self::assertSame($primarySessionId, $this->sessionStore()->getId());
        self::assertSame($primarySessionId, $authSession->refresh()->session_id);
        self::assertNull($pending->refresh()->completed_at);
        $this->assertAuthenticatedAs($user);
        self::assertTrue(DB::table('sessions')->where('id', $primarySessionId)->exists());
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.session.persistence_failed']);
    }

    public function test_later_login_transaction_failure_rolls_back_the_new_browser_authentication(): void
    {
        $user = User::factory()->active()->create();
        $this->post('/login/otp', ['email' => $user->email]);
        AuthChallenge::query()->sole()->update(['delivered_at' => now()]);
        $dispatcher = SecurityEvent::getEventDispatcher();
        self::assertNotNull($dispatcher);
        SecurityEvent::setEventDispatcher(clone $dispatcher);
        SecurityEvent::creating(static function (SecurityEvent $event): void {
            if ($event->event_code === 'identity.authentication.succeeded') {
                throw new RuntimeException('Synthetic downstream login failure.');
            }
        });

        try {
            $this->withoutExceptionHandling();
            $this->post('/login/verify', ['code' => $this->queuedOtpCode()]);
            self::fail('The synthetic downstream login failure was not raised.');
        } catch (RuntimeException $exception) {
            self::assertSame('Synthetic downstream login failure.', $exception->getMessage());
        } finally {
            SecurityEvent::setEventDispatcher($dispatcher);
        }

        $this->assertGuest();
        self::assertSame(0, AuthSession::query()->count());
    }

    public function test_later_primary_reauthentication_failure_restores_the_pre_rotation_session(): void
    {
        $user = User::factory()->active()->mfaConfirmed()->create();
        $authSession = $this->authenticate($user);
        $originalSessionId = $authSession->session_id;
        $this->post('/reauthenticate', ['return_route' => 'identity.security.index']);
        AuthChallenge::query()->sole()->update(['delivered_at' => now()]);
        $dispatcher = PendingAuthentication::getEventDispatcher();
        self::assertNotNull($dispatcher);
        PendingAuthentication::setEventDispatcher(clone $dispatcher);
        PendingAuthentication::creating(static function (): never {
            throw new RuntimeException('Synthetic downstream reauthentication failure.');
        });

        try {
            $this->withoutExceptionHandling();
            $this->post('/reauthenticate/verify', ['code' => $this->queuedOtpCode()]);
            self::fail('The synthetic downstream reauthentication failure was not raised.');
        } catch (RuntimeException $exception) {
            self::assertSame('Synthetic downstream reauthentication failure.', $exception->getMessage());
        } finally {
            PendingAuthentication::setEventDispatcher($dispatcher);
        }

        self::assertSame($originalSessionId, $this->sessionStore()->getId());
        self::assertSame($originalSessionId, $authSession->refresh()->session_id);
        $this->assertAuthenticatedAs($user);
    }

    private function beginPrivilegedLogin(User $user): string
    {
        $this->post('/login/otp', ['email' => $user->email]);
        AuthChallenge::query()->where('purpose', AuthenticationPurpose::Login)->sole()->update(['delivered_at' => now()]);
        $this->post('/login/verify', ['code' => $this->queuedOtpCode()])->assertRedirect('/login/mfa');
        $sessionId = $this->sessionStore()->getId();
        $this->withCookie((string) config('session.cookie'), $sessionId);

        return $sessionId;
    }

    private function authenticate(User $user): AuthSession
    {
        $session = $this->sessionStore();
        $session->start();
        $session->setId(bin2hex(random_bytes(20)));
        $this->actingAs($user);
        $this->withCookie((string) config('session.cookie'), $session->getId());
        $authSession = AuthSession::query()->create([
            'session_id' => $session->getId(),
            'user_id' => $user->id,
            'started_at' => now()->subHour(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHours(7),
            'primary_authenticated_at' => now()->subHour(),
            'mfa_authenticated_at' => now()->subHour(),
            'reauthenticated_at' => now()->subHour(),
            'user_session_version' => $user->session_version,
        ]);

        return $authSession;
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
