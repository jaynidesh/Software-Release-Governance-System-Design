<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Mfa\RotateTotp;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Models\UserRecoveryCode;
use App\Services\Identity\RecoveryCodeHasher;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use OTPHP\TOTP;
use Tests\TestCase;

final class PrivilegedReauthenticationTest extends TestCase
{
    use RefreshDatabase;

    public function test_reauthentication_starts_only_after_an_explicit_post(): void
    {
        $user = User::factory()->active()->mfaConfirmed()->create();
        $this->authenticate($user, now()->subHour());

        $this->get('/reauthenticate')
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private');

        self::assertSame(0, AuthChallenge::query()->count());
        self::assertSame(0, DB::table('jobs')->count());

        $this->post('/reauthenticate', ['return_route' => 'identity.security.index'])
            ->assertRedirect('/reauthenticate')
            ->assertSessionHas('status', 'A verification code has been sent.');

        $this->assertAuthenticatedAs($user);
        self::assertSame(AuthenticationPurpose::Reauthentication, AuthChallenge::query()->sole()->purpose);
    }

    public function test_reauthentication_cannot_start_without_a_retained_confirmed_mfa_method(): void
    {
        $user = User::factory()->active()->create();
        $this->authenticate($user, now()->subHour());

        $this->post('/reauthenticate')->assertRedirect()->assertSessionHasErrors('domain');

        self::assertSame(0, AuthChallenge::query()->count());
    }

    public function test_removing_the_mfa_method_after_email_start_cannot_downgrade_reauthentication(): void
    {
        $user = User::factory()->active()->mfaConfirmed()->create();
        $authSession = $this->authenticate($user, now()->subHour());
        $originalFreshness = $authSession->reauthenticated_at;
        $this->beginReauthentication($user);
        $user->mfaMethods()->sole()->update(['disabled_at' => now()]);

        $this->post('/reauthenticate/verify', ['code' => $this->queuedOtpCode()])
            ->assertRedirect('/reauthenticate')
            ->assertSessionHasErrors('code');

        self::assertTrue($authSession->refresh()->reauthenticated_at?->equalTo($originalFreshness));
        self::assertSame(0, PendingAuthentication::query()->count());
        $this->assertAuthenticatedAs($user);
    }

    public function test_primary_reauthentication_rekeys_without_refreshing_freshness_and_keeps_ordinary_access(): void
    {
        $this->travelTo('2026-09-23 10:00:00');
        $user = User::factory()->active()->mfaConfirmed()->create();
        $authSession = $this->authenticate($user, now()->subHour());
        $oldSessionId = $authSession->session_id;
        $oldReauthenticatedAt = $authSession->reauthenticated_at;
        $this->beginReauthentication($user);

        $this->post('/reauthenticate/verify', ['code' => $this->queuedOtpCode()])
            ->assertRedirect('/reauthenticate/mfa');
        $this->withCookie((string) config('session.cookie'), $this->sessionStore()->getId());

        $authSession->refresh();
        self::assertNotSame($oldSessionId, $authSession->session_id);
        self::assertSame($this->sessionStore()->getId(), $authSession->session_id);
        self::assertTrue($authSession->reauthenticated_at?->equalTo($oldReauthenticatedAt));
        self::assertNull(PendingAuthentication::query()->sole()->completed_at);
        $this->assertAuthenticatedAs($user);
        $this->get('/')->assertOk();
    }

    public function test_totp_completion_rekeys_again_refreshes_freshness_and_returns_to_allow_listed_route(): void
    {
        $this->travelTo('2026-09-23 10:00:00');
        $user = User::factory()->active()->mfaConfirmed()->create();
        $authSession = $this->authenticate($user, now()->subHour());
        $this->beginReauthentication($user, 'identity.security.index');
        $this->post('/reauthenticate/verify', ['code' => $this->queuedOtpCode()]);
        $this->withCookie((string) config('session.cookie'), $this->sessionStore()->getId());
        $primarySessionId = $authSession->refresh()->session_id;
        $method = $user->mfaMethods()->sole();

        $this->travel(5)->seconds();
        $this->post('/reauthenticate/mfa', [
            'code' => TOTP::createFromSecret($method->secret)->now(),
        ])->assertRedirect('/security');

        $authSession->refresh();
        self::assertNotSame($primarySessionId, $authSession->session_id);
        self::assertTrue($authSession->mfa_authenticated_at?->equalTo(now()));
        self::assertTrue($authSession->reauthenticated_at?->equalTo(now()));
        self::assertNotNull(PendingAuthentication::query()->sole()->completed_at);
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.reauthentication.succeeded']);
    }

    public function test_recovery_code_can_complete_reauthentication_once(): void
    {
        $user = User::factory()->active()->mfaConfirmed()->create();
        $authSession = $this->authenticate($user, now()->subHour());
        $method = $user->mfaMethods()->sole();
        $plain = 'ABCD-EFGH-JK23';
        $recovery = UserRecoveryCode::query()->create([
            'user_mfa_method_id' => $method->id,
            'code_hmac' => $this->app->make(RecoveryCodeHasher::class)->hash($plain, $method->id),
        ]);
        $this->beginReauthentication($user);
        $this->post('/reauthenticate/verify', ['code' => $this->queuedOtpCode()]);
        $this->withCookie((string) config('session.cookie'), $this->sessionStore()->getId());

        $this->post('/reauthenticate/mfa', ['code' => $plain])->assertRedirect('/security');

        self::assertNotNull($recovery->refresh()->used_at);
        self::assertNotNull($authSession->refresh()->reauthenticated_at);
    }

    public function test_untrusted_return_route_is_replaced_with_the_safe_default(): void
    {
        $user = User::factory()->active()->mfaConfirmed()->create();
        $this->authenticate($user, now()->subHour());
        $this->beginReauthentication($user, 'https://attacker.example/steal');
        $this->post('/reauthenticate/verify', ['code' => $this->queuedOtpCode()]);
        $this->withCookie((string) config('session.cookie'), $this->sessionStore()->getId());

        $this->post('/reauthenticate/mfa', [
            'code' => TOTP::createFromSecret($user->mfaMethods()->sole()->secret)->now(),
        ])->assertRedirect('/security');
    }

    public function test_freshness_middleware_denies_credential_mutation_without_implicitly_sending_otp(): void
    {
        $user = User::factory()->active()->mfaConfirmed()->create();
        $this->authenticate($user, now()->subHour());

        $this->post('/security/recovery-codes')->assertRedirect('/reauthenticate');

        self::assertSame(0, AuthChallenge::query()->count());
        self::assertSame(0, UserRecoveryCode::query()->count());
    }

    public function test_fresh_session_can_regenerate_recovery_codes_through_protected_route(): void
    {
        $this->withoutVite();
        $user = User::factory()->active()->mfaConfirmed()->create();
        $this->authenticate($user, now());

        $response = $this->post('/security/recovery-codes')->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private');

        self::assertSame((int) config('identity.totp.recovery_code_count'), UserRecoveryCode::query()->count());
        $response->assertSee('They will not be shown again.');
    }

    public function test_rotation_sets_a_new_enrollment_age_anchor_as_well_as_rotated_at(): void
    {
        $this->travelTo('2026-09-23 10:00:00');
        $user = User::factory()->active()->mfaConfirmed()->create();
        $method = $user->mfaMethods()->sole();
        $method->forceFill(['created_at' => now()->subYear()])->save();
        $this->authenticate($user, now());
        $this->app->make(RotateTotp::class)->handle($user, null, null, null);

        $method->refresh();
        self::assertTrue($method->rotated_at?->equalTo(now()));
        self::assertTrue($method->created_at?->equalTo(now()));
    }

    private function beginReauthentication(User $user, string $returnRoute = 'identity.security.index'): void
    {
        $this->post('/reauthenticate', ['return_route' => $returnRoute]);
        $challenge = AuthChallenge::query()->where('user_id', $user->id)->latest('id')->firstOrFail();
        $challenge->update(['delivered_at' => now()]);
    }

    private function authenticate(User $user, mixed $reauthenticatedAt): AuthSession
    {
        $session = $this->sessionStore();
        $session->start();
        $session->setId(bin2hex(random_bytes(20)));
        $this->actingAs($user);
        $this->withCookie((string) config('session.cookie'), $session->getId());

        return AuthSession::query()->create([
            'session_id' => $session->getId(),
            'user_id' => $user->id,
            'started_at' => now()->subHour(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHours(7),
            'primary_authenticated_at' => now()->subHour(),
            'mfa_authenticated_at' => now()->subHour(),
            'reauthenticated_at' => $reauthenticatedAt,
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

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }
}
