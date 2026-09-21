<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Domain\Identity\Enums\PermissionScope;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\LoginEvent;
use App\Models\PendingAuthentication;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Models\UserRecoveryCode;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use LogicException;
use Tests\TestCase;

final class PasswordlessSchemaTest extends TestCase
{
    use RefreshDatabase;

    public function test_users_are_passwordless_typed_identity_records_with_public_ulids(): void
    {
        self::assertFalse(Schema::hasColumn('users', 'password'));
        self::assertFalse(Schema::hasColumn('users', 'remember_token'));
        self::assertFalse(Schema::hasTable('password_reset_tokens'));

        $user = User::factory()->active()->create();

        self::assertTrue(Str::isUlid($user->public_id));
        self::assertSame('public_id', $user->getRouteKeyName());
        self::assertSame(UserState::Active, $user->state);
        self::assertNotNull($user->activated_at);
        self::assertNotNull($user->email_verified_at);
        self::assertSame('UTC', $user->timezone);
        self::assertSame(1, $user->session_version);
    }

    public function test_passwordless_user_factory_exposes_each_lifecycle_state_and_lockout(): void
    {
        self::assertSame(UserState::Invited, User::factory()->invited()->create()->state);
        self::assertSame(UserState::Active, User::factory()->active()->create()->state);
        self::assertSame(UserState::Suspended, User::factory()->suspended()->create()->state);
        self::assertSame(UserState::Deactivated, User::factory()->deactivated()->create()->state);

        $locked = User::factory()->locked()->create();
        self::assertSame((int) config('identity.lockout.attempts'), $locked->failed_auth_attempts);
        self::assertTrue($locked->locked_until->isFuture());
    }

    public function test_privileged_factory_persists_a_global_assignment_with_a_canonical_privileged_permission(): void
    {
        $user = User::factory()->privileged()->create();
        $assignment = $user->roleAssignments()->with('role.permissions')->sole();
        $permission = $assignment->role->permissions->firstWhere('code', 'admin.users');

        self::assertNull($assignment->application_id);
        self::assertTrue($assignment->role->is_system);
        self::assertTrue($assignment->role->is_active);
        self::assertNotNull($permission);
        self::assertSame(PermissionScope::Global, $permission->scope_type);
    }

    public function test_privileged_factory_preserves_the_seeded_administrator_permission_bundle(): void
    {
        $this->seed();
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        $permissionsBefore = $administrator->permissions()->orderBy('code')->pluck('code')->all();

        User::factory()->privileged()->create();

        self::assertSame(
            $permissionsBefore,
            $administrator->permissions()->orderBy('code')->pluck('code')->all(),
        );
    }

    public function test_authorization_models_have_typed_relationships_and_public_route_keys(): void
    {
        $user = User::factory()->active()->create();
        $application = Application::factory()->create();
        $role = Role::factory()->create();
        $permission = Permission::factory()->create(['scope_type' => PermissionScope::Application]);
        $role->permissions()->attach($permission);
        $assignment = RoleAssignment::factory()->for($user)->for($role)->for($application)->create();

        foreach ([$user, $application, $role, $assignment] as $model) {
            self::assertTrue(Str::isUlid($model->public_id));
            self::assertSame('public_id', $model->getRouteKeyName());
        }

        self::assertInstanceOf(HasMany::class, $user->roleAssignments());
        self::assertInstanceOf(HasMany::class, $application->roleAssignments());
        self::assertInstanceOf(BelongsToMany::class, $role->permissions());
        self::assertInstanceOf(BelongsToMany::class, $permission->roles());
        self::assertInstanceOf(BelongsTo::class, $assignment->user());
        self::assertInstanceOf(BelongsTo::class, $assignment->role());
        self::assertInstanceOf(BelongsTo::class, $assignment->application());
        self::assertTrue($assignment->starts_at->isPast());
    }

    public function test_authentication_records_cast_enums_timestamps_and_encrypted_secrets(): void
    {
        $user = User::factory()->active()->create();
        $challenge = AuthChallenge::create([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'code_hmac' => 'challenge-hmac',
            'expires_at' => now()->addMinutes(10),
        ]);
        $pending = PendingAuthentication::create([
            'user_id' => $user->id,
            'auth_challenge_id' => $challenge->id,
            'purpose' => AuthenticationPurpose::Login,
            'session_id_hmac' => 'session-hmac',
            'user_session_version' => 1,
            'expires_at' => now()->addMinutes(10),
        ]);
        $method = UserMfaMethod::create([
            'user_id' => $user->id,
            'type' => MfaMethodType::Totp,
            'secret' => 'shared-secret',
        ]);
        $recoveryCode = UserRecoveryCode::create([
            'user_mfa_method_id' => $method->id,
            'code_hmac' => 'recovery-hmac',
        ]);

        self::assertSame(AuthenticationPurpose::Login, $challenge->purpose);
        self::assertSame(AuthenticationPurpose::Login, $pending->purpose);
        self::assertSame(MfaMethodType::Totp, $method->type);
        self::assertNotSame('shared-secret', $method->getRawOriginal('secret'));
        self::assertSame('shared-secret', $method->secret);
        self::assertSame($challenge->id, $pending->challenge->id);
        self::assertSame($method->id, $recoveryCode->mfaMethod->id);

        self::assertArrayNotHasKey('code_hmac', $challenge->toArray());
        self::assertArrayNotHasKey('session_id_hmac', $pending->toArray());
        self::assertArrayNotHasKey('secret', $method->toArray());
        self::assertArrayNotHasKey('code_hmac', $recoveryCode->toArray());
    }

    public function test_session_and_event_identifiers_are_hidden_and_events_are_append_only(): void
    {
        $user = User::factory()->active()->create();
        $authSession = AuthSession::create([
            'session_id' => 'private-session-id',
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHours(8),
            'primary_authenticated_at' => now(),
            'user_session_version' => 1,
        ]);
        $loginEvent = LoginEvent::create([
            'user_id' => $user->id,
            'identifier_hmac' => 'identifier-hmac',
            'purpose' => AuthenticationPurpose::Login,
            'result_code' => 'SUCCESS',
            'occurred_at' => now(),
        ]);
        $securityEvent = SecurityEvent::create([
            'actor_id' => $user->id,
            'subject_user_id' => $user->id,
            'event_code' => 'identity.tested',
            'schema_version' => 1,
            'metadata' => ['safe' => true],
            'occurred_at' => now(),
        ]);

        self::assertTrue(Str::isUlid($authSession->public_id));
        self::assertSame('public_id', $authSession->getRouteKeyName());
        self::assertArrayNotHasKey('session_id', $authSession->toArray());
        self::assertArrayNotHasKey('identifier_hmac', $loginEvent->toArray());
        self::assertSame(['safe' => true], $securityEvent->metadata);

        try {
            $loginEvent->update(['result_code' => 'ALTERED']);
            self::fail('Login events must reject updates.');
        } catch (LogicException) {
            self::assertSame('SUCCESS', $loginEvent->fresh()->result_code);
        }

        $this->expectException(LogicException::class);
        $securityEvent->delete();
    }
}
