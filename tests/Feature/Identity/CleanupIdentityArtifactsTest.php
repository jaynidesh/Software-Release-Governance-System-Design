<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\LoginEvent;
use App\Models\PendingAuthentication;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Models\UserMfaMethod;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

final class CleanupIdentityArtifactsTest extends TestCase
{
    use RefreshDatabase;

    public function test_cleanup_is_chunked_idempotent_and_preserves_fresh_state_and_append_only_events(): void
    {
        $this->travelTo('2026-09-29 12:00:00');
        config()->set('identity.challenge_retention_hours', 24);
        config()->set('identity.totp.unconfirmed_ttl_minutes', 30);
        $user = User::factory()->active()->create();

        $staleChallenges = collect([
            $this->challenge($user, now()->subHours(25), now()->subHours(26)),
            $this->challenge($user, now()->subHours(25), now()->subHours(26)),
        ]);
        $freshExpiredChallenge = $this->challenge($user, now()->subHour(), now()->subHours(2));
        $stalePending = $staleChallenges->map(fn (AuthChallenge $challenge): PendingAuthentication => $this->pending(
            $user,
            $challenge,
            now()->subHours(25),
            now()->subHours(26),
        ));
        $freshPending = $this->pending(
            $user,
            $freshExpiredChallenge,
            now()->addMinute(),
            now()->subMinutes(9),
        );
        $recentlyInvalidatedChallenge = $this->challenge($user, now()->addHour(), now()->subHours(26));
        $recentlyInvalidatedChallenge->update(['invalidated_at' => now()]);
        $recentlyInvalidatedPending = $this->pending(
            $user,
            $recentlyInvalidatedChallenge,
            now()->addHour(),
            now()->subHours(26),
        );
        $recentlyInvalidatedPending->update(['invalidated_at' => now()]);

        $staleMethods = collect([
            $this->mfaMethod($user, now()->subMinutes(31)),
            $this->mfaMethod(User::factory()->active()->create(), now()->subMinutes(31)),
        ]);
        $freshMethod = $this->mfaMethod(User::factory()->active()->create(), now()->subMinutes(29));
        $confirmedMethod = $this->mfaMethod(User::factory()->active()->create(), now()->subHour(), now()->subMinute());

        $metadataOrphans = collect([
            $this->authSession($user, Str::random(40), now()->subMinutes(6)),
            $this->authSession($user, Str::random(40), now()->subMinutes(6)),
        ]);
        $freshMetadataOrphan = $this->authSession($user, Str::random(40), now()->subMinutes(4));
        $payloadOrphanIds = collect([Str::random(40), Str::random(40)]);
        $payloadOrphanIds->each(fn (string $id) => $this->payload($id, $user, now()->subMinutes(6)->timestamp));
        $freshPayloadOrphanId = Str::random(40);
        $this->payload($freshPayloadOrphanId, $user, now()->subMinutes(4)->timestamp);
        $pairedSession = $this->authSession($user, Str::random(40), now()->subMinutes(6));
        $this->payload($pairedSession->session_id, $user, now()->subMinutes(6)->timestamp);

        $loginEvent = LoginEvent::query()->create([
            'user_id' => $user->id,
            'identifier_hmac' => str_repeat('a', 64),
            'purpose' => AuthenticationPurpose::Login,
            'result_code' => 'OTP_REQUEST_ACCEPTED',
            'occurred_at' => now()->subYears(10),
        ]);
        $securityEvent = SecurityEvent::query()->create([
            'actor_id' => $user->id,
            'subject_user_id' => $user->id,
            'event_code' => 'identity.test.event',
            'schema_version' => 1,
            'metadata' => [],
            'occurred_at' => now()->subYears(10),
        ]);

        $this->artisan('identity:cleanup', ['--chunk' => 1])
            ->expectsOutputToContain('pending authentications: 2')
            ->expectsOutputToContain('authentication challenges: 2')
            ->expectsOutputToContain('unconfirmed MFA methods: 2')
            ->expectsOutputToContain('Orphan auth sessions: 2')
            ->expectsOutputToContain('Orphan session payloads: 2')
            ->assertSuccessful();

        self::assertFalse(PendingAuthentication::query()->whereKey($stalePending->pluck('id'))->exists());
        self::assertFalse(AuthChallenge::query()->whereKey($staleChallenges->pluck('id'))->exists());
        self::assertFalse(UserMfaMethod::query()->whereKey($staleMethods->pluck('id'))->exists());
        self::assertFalse(AuthSession::query()->whereKey($metadataOrphans->pluck('id'))->exists());
        self::assertFalse(DB::table('sessions')->whereIn('id', $payloadOrphanIds)->exists());
        self::assertTrue(PendingAuthentication::query()->whereKey($freshPending->id)->exists());
        self::assertTrue(AuthChallenge::query()->whereKey($freshExpiredChallenge->id)->exists());
        self::assertTrue(PendingAuthentication::query()->whereKey($recentlyInvalidatedPending->id)->exists());
        self::assertTrue(AuthChallenge::query()->whereKey($recentlyInvalidatedChallenge->id)->exists());
        self::assertTrue(UserMfaMethod::query()->whereKey($freshMethod->id)->exists());
        self::assertTrue(UserMfaMethod::query()->whereKey($confirmedMethod->id)->exists());
        self::assertTrue(AuthSession::query()->whereKey($freshMetadataOrphan->id)->exists());
        self::assertTrue(DB::table('sessions')->where('id', $freshPayloadOrphanId)->exists());
        self::assertTrue(AuthSession::query()->whereKey($pairedSession->id)->exists());
        self::assertTrue(DB::table('sessions')->where('id', $pairedSession->session_id)->exists());
        self::assertTrue(LoginEvent::query()->whereKey($loginEvent->id)->exists());
        self::assertTrue(SecurityEvent::query()->whereKey($securityEvent->id)->exists());

        $this->artisan('identity:cleanup', ['--chunk' => 1])
            ->expectsOutputToContain('pending authentications: 0')
            ->expectsOutputToContain('authentication challenges: 0')
            ->expectsOutputToContain('unconfirmed MFA methods: 0')
            ->expectsOutputToContain('Orphan auth sessions: 0')
            ->expectsOutputToContain('Orphan session payloads: 0')
            ->assertSuccessful();
    }

    private function challenge(User $user, mixed $expiresAt, mixed $createdAt): AuthChallenge
    {
        $challenge = AuthChallenge::query()->create([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'code_hmac' => str_repeat('b', 64),
            'expires_at' => $expiresAt,
            'invalidated_at' => $expiresAt,
        ]);
        AuthChallenge::withoutTimestamps(fn () => $challenge->forceFill([
            'created_at' => $createdAt,
            'updated_at' => $createdAt,
        ])->save());

        return $challenge;
    }

    private function pending(User $user, AuthChallenge $challenge, mixed $expiresAt, mixed $createdAt): PendingAuthentication
    {
        $pending = PendingAuthentication::query()->create([
            'user_id' => $user->id,
            'auth_challenge_id' => $challenge->id,
            'purpose' => AuthenticationPurpose::Login,
            'session_id_hmac' => str_repeat('c', 64),
            'user_session_version' => $user->session_version,
            'expires_at' => $expiresAt,
            'invalidated_at' => $expiresAt,
        ]);
        PendingAuthentication::withoutTimestamps(fn () => $pending->forceFill([
            'created_at' => $createdAt,
            'updated_at' => $createdAt,
        ])->save());

        return $pending;
    }

    private function mfaMethod(User $user, mixed $createdAt, mixed $confirmedAt = null): UserMfaMethod
    {
        $method = UserMfaMethod::query()->create([
            'user_id' => $user->id,
            'type' => MfaMethodType::Totp,
            'secret' => 'TESTONLYSHAREDSECRET',
            'confirmed_at' => $confirmedAt,
        ]);
        UserMfaMethod::withoutTimestamps(fn () => $method->forceFill([
            'created_at' => $createdAt,
            'updated_at' => $createdAt,
        ])->save());

        return $method;
    }

    private function authSession(User $user, string $sessionId, mixed $updatedAt): AuthSession
    {
        $authSession = AuthSession::query()->create([
            'session_id' => $sessionId,
            'user_id' => $user->id,
            'started_at' => now()->subHour(),
            'last_seen_at' => now()->subHour(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now()->subHour(),
            'user_session_version' => $user->session_version,
        ]);
        AuthSession::withoutTimestamps(fn () => $authSession->forceFill([
            'created_at' => $updatedAt,
            'updated_at' => $updatedAt,
        ])->save());

        return $authSession;
    }

    private function payload(string $sessionId, User $user, int $lastActivity): void
    {
        DB::table('sessions')->insert([
            'id' => $sessionId,
            'user_id' => $user->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Cleanup test',
            'payload' => base64_encode('payload'),
            'last_activity' => $lastActivity,
        ]);
    }
}
