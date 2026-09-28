<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Domain\Identity\Enums\MfaMethodType;
use App\Domain\Identity\Enums\UserState;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Models\UserRecoveryCode;
use App\Notifications\Identity\AdministratorRecoveryNotification;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

final class RecoverAdministratorCommandTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->seed(IdentityAuthorizationSeeder::class);
    }

    public function test_recovery_is_interactive_only_and_rejects_non_principals_or_suspended_users(): void
    {
        $ordinary = User::factory()->active()->create(['email' => 'ordinary@example.test']);
        $this->artisan('identity:recover-admin', ['--no-interaction' => true])
            ->expectsOutputToContain('interactive')
            ->assertFailed();

        $this->artisan('identity:recover-admin')
            ->expectsQuestion('Administrator email', $ordinary->email)
            ->expectsQuestion('Incident reference', 'INC-1')
            ->expectsQuestion('Recovery reason', 'Lost authenticator')
            ->expectsQuestion('Type exactly "RECOVER ordinary@example.test" to continue', 'RECOVER ordinary@example.test')
            ->expectsOutputToContain('eligible administrator principal')
            ->assertFailed();

        self::assertSame(UserState::Active, $ordinary->refresh()->state);
    }

    public function test_recovery_requires_exact_confirmation_and_invalidates_all_authentication_state_with_incident_event(): void
    {
        Notification::fake();
        $user = User::factory()->active()->create([
            'email' => 'admin@example.test',
            'session_version' => 4,
        ]);
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        RoleAssignment::factory()->create(['user_id' => $user->id, 'role_id' => $administrator->id]);
        $method = UserMfaMethod::query()->create([
            'user_id' => $user->id,
            'type' => MfaMethodType::Totp,
            'secret' => 'TESTONLYSHAREDSECRET',
            'confirmed_at' => now(),
        ]);
        UserRecoveryCode::query()->create([
            'user_mfa_method_id' => $method->id,
            'code_hmac' => str_repeat('a', 64),
        ]);
        AuthChallenge::query()->create([
            'user_id' => $user->id,
            'purpose' => 'LOGIN',
            'code_hmac' => str_repeat('b', 64),
            'expires_at' => now()->addMinute(),
        ]);
        AuthSession::query()->create([
            'session_id' => 'recovery-session',
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'user_session_version' => 4,
        ]);

        $this->artisan('identity:recover-admin')
            ->expectsQuestion('Administrator email', ' ADMIN@EXAMPLE.TEST ')
            ->expectsQuestion('Incident reference', ' INC-2026-0042 ')
            ->expectsQuestion('Recovery reason', ' Lost hardware authenticator ')
            ->expectsQuestion('Type exactly "RECOVER admin@example.test" to continue', 'recover admin@example.test')
            ->expectsOutputToContain('Confirmation did not match')
            ->assertFailed();
        self::assertSame(4, $user->refresh()->session_version);

        $this->artisan('identity:recover-admin')
            ->expectsQuestion('Administrator email', ' ADMIN@EXAMPLE.TEST ')
            ->expectsQuestion('Incident reference', ' INC-2026-0042 ')
            ->expectsQuestion('Recovery reason', ' Lost hardware authenticator ')
            ->expectsQuestion('Type exactly "RECOVER admin@example.test" to continue', 'RECOVER admin@example.test')
            ->assertSuccessful();

        $user->refresh();
        self::assertSame(5, $user->session_version);
        self::assertSame(UserState::Invited, $user->state);
        self::assertNotNull($user->invitation_expires_at);
        self::assertNotNull($method->refresh()->disabled_at);
        self::assertSame(0, UserRecoveryCode::query()->count());
        self::assertNotNull(AuthChallenge::query()->sole()->invalidated_at);
        self::assertSame(0, AuthSession::query()->where('user_id', $user->id)->count());
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.administrator.recovered']);
        $event = $user->securityEvents ?? null;
        $metadata = SecurityEvent::query()->where('event_code', 'identity.administrator.recovered')->sole()->metadata;
        self::assertSame('INC-2026-0042', $metadata['incident_reference']);
        self::assertSame('Lost hardware authenticator', $metadata['reason']);
        Notification::assertSentTo($user, AdministratorRecoveryNotification::class);
    }
}
