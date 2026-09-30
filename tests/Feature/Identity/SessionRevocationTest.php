<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Contracts\Identity\AuthorizationService;
use App\Models\Application;
use App\Models\AuthSession;
use App\Models\User;
use App\Services\Identity\AuthenticatedSessionManager;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class SessionRevocationTest extends TestCase
{
    use RefreshDatabase;

    public function test_security_overview_lists_public_session_references_without_raw_ids(): void
    {
        $this->withoutVite();
        $user = User::factory()->active()->create();
        $current = $this->authenticate($user);
        $other = $this->storedSession($user, 'Other Browser');

        $response = $this->get('/security')->assertOk();

        $response->assertSee($current->public_id)
            ->assertSee($other->public_id)
            ->assertDontSee($current->session_id)
            ->assertDontSee($other->session_id);
    }

    public function test_user_can_revoke_another_own_session_and_both_internal_rows_are_deleted(): void
    {
        $user = User::factory()->active()->create();
        $this->authenticate($user);
        $other = $this->storedSession($user, 'Other Browser');

        $this->delete('/security/sessions/'.$other->public_id)->assertRedirect('/security');

        self::assertFalse(AuthSession::query()->whereKey($other->id)->exists());
        self::assertFalse(DB::table('sessions')->where('id', $other->session_id)->exists());
        $this->assertDatabaseHas('security_events', [
            'event_code' => 'identity.session.revoked',
            'actor_id' => $user->id,
            'subject_user_id' => $user->id,
        ]);
    }

    public function test_cross_user_revocation_is_denied(): void
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $this->authenticate($actor);
        $targetSession = $this->storedSession($target, 'Target Browser');

        $this->delete('/security/sessions/'.$targetSession->public_id)->assertForbidden();

        self::assertTrue(AuthSession::query()->whereKey($targetSession->id)->exists());
        self::assertTrue(DB::table('sessions')->where('id', $targetSession->session_id)->exists());
    }

    public function test_raw_session_id_is_not_accepted_as_a_route_identifier(): void
    {
        $user = User::factory()->active()->create();
        $this->authenticate($user);
        $other = $this->storedSession($user, 'Other Browser');

        $this->delete('/security/sessions/'.$other->session_id)->assertNotFound();

        self::assertTrue(AuthSession::query()->whereKey($other->id)->exists());
    }

    public function test_fresh_administrator_can_revoke_another_users_session_through_the_action_boundary(): void
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $this->authenticate($actor, true);
        $targetSession = $this->storedSession($target, 'Target Browser');
        $this->app->bind(AuthorizationService::class, static fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $permission === 'admin.users' && $requiresFreshReauthentication;
            }
        });

        $this->delete('/security/sessions/'.$targetSession->public_id)->assertRedirect('/security');

        self::assertFalse(AuthSession::query()->whereKey($targetSession->id)->exists());
        $this->assertDatabaseHas('security_events', [
            'event_code' => 'identity.session.revoked',
            'actor_id' => $actor->id,
            'subject_user_id' => $target->id,
        ]);
    }

    public function test_revoke_all_increments_session_version_deletes_every_payload_and_logs_out_actor(): void
    {
        $user = User::factory()->active()->create();
        $current = $this->authenticate($user);
        $other = $this->storedSession($user, 'Other Browser');

        $this->delete('/security/sessions')->assertRedirect('/login');

        $this->assertGuest();
        self::assertSame(2, $user->refresh()->session_version);
        self::assertSame(0, AuthSession::query()->where('user_id', $user->id)->count());
        self::assertFalse(DB::table('sessions')->whereIn('id', [$current->session_id, $other->session_id])->exists());
    }

    public function test_orphan_cleanup_removes_metadata_without_payload_and_authenticated_payload_without_metadata(): void
    {
        $user = User::factory()->active()->create();
        $metadataOrphan = AuthSession::query()->create($this->metadata($user, bin2hex(random_bytes(20)), 'Metadata orphan'));
        AuthSession::withoutTimestamps(function () use ($metadataOrphan): void {
            $metadataOrphan->forceFill([
                'created_at' => now()->subMinutes(6),
                'updated_at' => now()->subMinutes(6),
            ])->save();
        });
        $payloadOrphanId = bin2hex(random_bytes(20));
        $this->insertPayload($payloadOrphanId, $user, now()->subMinutes(6)->timestamp);
        $valid = $this->storedSession($user, 'Valid');
        $freshMetadata = AuthSession::query()->create($this->metadata($user, bin2hex(random_bytes(20)), 'Pending response'));
        $freshPayloadId = bin2hex(random_bytes(20));
        $this->insertPayload($freshPayloadId, $user);

        $result = $this->app->make(AuthenticatedSessionManager::class)->purgeOrphans();

        self::assertSame(['metadata' => 1, 'payloads' => 1], $result);
        self::assertFalse(AuthSession::query()->whereKey($metadataOrphan->id)->exists());
        self::assertFalse(DB::table('sessions')->where('id', $payloadOrphanId)->exists());
        self::assertTrue(AuthSession::query()->whereKey($valid->id)->exists());
        self::assertTrue(DB::table('sessions')->where('id', $valid->session_id)->exists());
        self::assertTrue(AuthSession::query()->whereKey($freshMetadata->id)->exists());
        self::assertTrue(DB::table('sessions')->where('id', $freshPayloadId)->exists());
    }

    public function test_orphan_cleanup_retains_old_metadata_that_was_freshly_rekeyed_before_its_payload_is_written(): void
    {
        $user = User::factory()->active()->create();
        $authSession = $this->authenticate($user);
        AuthSession::withoutTimestamps(function () use ($authSession): void {
            $authSession->forceFill([
                'created_at' => now()->subMinutes(6),
                'updated_at' => now()->subMinutes(6),
            ])->save();
        });

        $this->app->make(AuthenticatedSessionManager::class)->rekey($user, false);
        $rekeyedSessionId = $authSession->refresh()->session_id;
        self::assertFalse(DB::table('sessions')->where('id', $rekeyedSessionId)->exists());

        $result = $this->app->make(AuthenticatedSessionManager::class)->purgeOrphans();

        self::assertSame(['metadata' => 0, 'payloads' => 0], $result);
        self::assertTrue(AuthSession::query()->whereKey($authSession->id)->exists());
    }

    public function test_metadata_orphan_delete_rechecks_counterpart_and_freshness_after_candidate_discovery(): void
    {
        $user = User::factory()->active()->create();
        $paired = $this->authSessionOrphan($user, 'paired-after-discovery');
        $refreshed = $this->authSessionOrphan($user, 'refreshed-after-discovery');
        $interleaved = false;
        DB::listen(function (QueryExecuted $query) use ($user, $paired, $refreshed, &$interleaved): void {
            if ($interleaved
                || ! str_contains($query->sql, 'select `id` from `auth_sessions`')
                || ! str_contains($query->sql, 'not exists')
                || ! str_contains($query->sql, 'limit 500')) {
                return;
            }

            $interleaved = true;
            $this->insertPayload($paired->session_id, $user);
            AuthSession::withoutTimestamps(fn () => $refreshed->forceFill(['updated_at' => now()])->save());
        });

        $result = $this->app->make(AuthenticatedSessionManager::class)->purgeOrphans();

        self::assertTrue($interleaved);
        self::assertSame(['metadata' => 0, 'payloads' => 0], $result);
        self::assertTrue(AuthSession::query()->whereKey($paired->id)->exists());
        self::assertTrue(AuthSession::query()->whereKey($refreshed->id)->exists());
        self::assertTrue(DB::table('sessions')->where('id', $paired->session_id)->exists());
    }

    public function test_payload_orphan_delete_rechecks_counterpart_and_freshness_after_candidate_discovery(): void
    {
        $user = User::factory()->active()->create();
        $pairedId = 'payload-paired-after-discovery';
        $refreshedId = 'payload-refreshed-after-discovery';
        $this->insertPayload($pairedId, $user, now()->subMinutes(6)->timestamp);
        $this->insertPayload($refreshedId, $user, now()->subMinutes(6)->timestamp);
        $interleaved = false;
        DB::listen(function (QueryExecuted $query) use ($user, $pairedId, $refreshedId, &$interleaved): void {
            if ($interleaved
                || ! str_contains($query->sql, 'select `id` from `sessions`')
                || ! str_contains($query->sql, 'not exists')
                || ! str_contains($query->sql, 'limit 500')) {
                return;
            }

            $interleaved = true;
            AuthSession::query()->create($this->metadata($user, $pairedId, 'Paired after discovery'));
            DB::table('sessions')->where('id', $refreshedId)->update(['last_activity' => now()->timestamp]);
        });

        $result = $this->app->make(AuthenticatedSessionManager::class)->purgeOrphans();

        self::assertTrue($interleaved);
        self::assertSame(['metadata' => 0, 'payloads' => 0], $result);
        self::assertTrue(DB::table('sessions')->where('id', $pairedId)->exists());
        self::assertTrue(DB::table('sessions')->where('id', $refreshedId)->exists());
        self::assertTrue(AuthSession::query()->where('session_id', $pairedId)->exists());
    }

    private function authenticate(User $user, bool $fresh = false): AuthSession
    {
        $session = $this->app->make(Session::class);
        $session->start();
        $session->setId(bin2hex(random_bytes(20)));
        $this->actingAs($user);
        $this->withCookie((string) config('session.cookie'), $session->getId());
        $authSession = AuthSession::query()->create([
            ...$this->metadata($user, $session->getId(), 'Current Browser'),
            'mfa_authenticated_at' => $fresh ? now() : null,
            'reauthenticated_at' => $fresh ? now() : null,
        ]);

        return $authSession;
    }

    private function storedSession(User $user, string $agent): AuthSession
    {
        $authSession = AuthSession::query()->create($this->metadata($user, bin2hex(random_bytes(20)), $agent));
        $this->insertPayload($authSession->session_id, $user);

        return $authSession;
    }

    private function authSessionOrphan(User $user, string $agent): AuthSession
    {
        $authSession = AuthSession::query()->create($this->metadata($user, bin2hex(random_bytes(20)), $agent));
        AuthSession::withoutTimestamps(fn () => $authSession->forceFill([
            'created_at' => now()->subMinutes(6),
            'updated_at' => now()->subMinutes(6),
        ])->save());

        return $authSession;
    }

    /** @return array<string, mixed> */
    private function metadata(User $user, string $sessionId, string $agent): array
    {
        return [
            'session_id' => $sessionId,
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHours(8),
            'primary_authenticated_at' => now(),
            'user_session_version' => $user->session_version,
            'ip_address' => '127.0.0.1',
            'user_agent' => $agent,
        ];
    }

    private function insertPayload(string $sessionId, User $user, ?int $lastActivity = null): void
    {
        DB::table('sessions')->updateOrInsert(['id' => $sessionId], [
            'user_id' => $user->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Test Browser',
            'payload' => base64_encode('payload'),
            'last_activity' => $lastActivity ?? now()->timestamp,
        ]);
    }
}
