<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Domain\Identity\Enums\UserState;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class PendingAuthenticationTest extends TestCase
{
    use RefreshDatabase;

    public function test_direct_access_is_denied(): void
    {
        $this->get('/login/mfa/enroll')->assertRedirect('/login');
        $this->get('/login/mfa')->assertRedirect('/login');
    }

    #[DataProvider('invalidPendingStates')]
    public function test_invalid_or_copied_pending_state_is_invalidated(string $state): void
    {
        $user = User::factory()->privileged()->create();
        $pending = $this->pendingFor($user);

        match ($state) {
            'copied-session' => $pending->update(['session_id_hmac' => str_repeat('f', 64)]),
            'expired' => $pending->update(['expires_at' => now()->subSecond()]),
            'replayed' => $pending->update(['completed_at' => now()]),
            'cancelled' => $pending->update(['invalidated_at' => now()]),
            'state-change' => $user->update(['state' => UserState::Suspended]),
            'session-version' => $user->increment('session_version'),
            'lockout' => $user->update(['locked_until' => now()->addMinutes(30)]),
            'privilege-change' => $user->roleAssignments()->update(['revoked_at' => now()]),
            'new-primary' => $this->createNewerChallenge($user, $pending),
        };

        $this->get('/login/mfa/enroll')
            ->assertRedirect('/login')
            ->assertSessionMissing('identity.pending_authentication');
        self::assertNotNull($pending->refresh()->invalidated_at ?? $pending->completed_at);
        $this->assertGuest();
    }

    /** @return array<string, array{string}> */
    public static function invalidPendingStates(): array
    {
        return [
            'copied session' => ['copied-session'],
            'expiry' => ['expired'],
            'replay' => ['replayed'],
            'cancellation' => ['cancelled'],
            'state change' => ['state-change'],
            'session version change' => ['session-version'],
            'lockout' => ['lockout'],
            'privilege change' => ['privilege-change'],
            'new primary challenge' => ['new-primary'],
        ];
    }

    public function test_only_the_exact_next_step_is_reachable(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $this->pendingFor($user);

        $this->get('/login/mfa/enroll')->assertRedirect('/login/mfa');
        $this->get('/login/mfa')->assertOk();
    }

    private function pendingFor(User $user): PendingAuthentication
    {
        $this->post('/login/otp', ['email' => $user->email]);
        $challenge = AuthChallenge::query()->sole();
        $challenge->update(['delivered_at' => now()]);
        $this->post('/login/verify', ['code' => $this->queuedCode()]);
        $this->withCookie((string) config('session.cookie'), $this->sessionStore()->getId());

        return PendingAuthentication::query()->sole();
    }

    private function createNewerChallenge(User $user, PendingAuthentication $pending): void
    {
        AuthChallenge::query()->create([
            'user_id' => $user->id,
            'purpose' => $pending->purpose,
            'code_hmac' => str_repeat('b', 64),
            'expires_at' => now()->addMinutes(10),
        ]);
    }

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }

    private function queuedCode(): string
    {
        /** @var array{data: array{command: string}} $payload */
        $payload = json_decode((string) DB::table('jobs')->sole()->payload, true, flags: JSON_THROW_ON_ERROR);
        $serialized = $this->app->make(Encrypter::class)->decrypt($payload['data']['command']);
        self::assertIsString($serialized);
        $job = unserialize($serialized, ['allowed_classes' => true]);
        self::assertInstanceOf(SendQueuedNotifications::class, $job);

        return $job->notification->code;
    }
}
