<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Users\ChangeUserState;
use App\Application\Identity\Users\CreateInvitedUser;
use App\Application\Identity\Users\ResendInvitation;
use App\Application\Identity\Users\RevokeInvitation;
use App\Application\Identity\Users\RevokeUserSessions;
use App\Application\Identity\Users\UnlockUser;
use App\Application\Identity\Users\UpdateUser;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Support\Exceptions\DomainRuleViolation;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

final class UserAdministrationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->seed(IdentityAuthorizationSeeder::class);
    }

    public function test_create_with_initial_assignments_is_atomic_and_separately_authorized(): void
    {
        Notification::fake();
        $actor = User::factory()->active()->create();
        $role = Role::factory()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        try {
            $this->app->make(CreateInvitedUser::class)->handle(
                $actor,
                ['name' => 'New Person', 'email' => 'new@example.test', 'timezone' => 'UTC'],
                null,
                null,
                null,
                [['role' => $role, 'application' => null, 'starts_at' => now(), 'ends_at' => null]],
            );
            self::fail('Initial role grant bypassed admin.roles.');
        } catch (AuthorizationException) {
            $this->assertDatabaseMissing('users', ['email' => 'new@example.test']);
            Notification::assertNothingSent();
        }

        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users', 'admin.roles']));
        $inactiveApplication = Application::factory()->inactive()->create();

        try {
            $this->app->make(CreateInvitedUser::class)->handle(
                $actor,
                ['name' => 'Rollback Person', 'email' => 'rollback@example.test', 'timezone' => 'UTC'],
                null,
                null,
                null,
                [['role' => $role, 'application' => $inactiveApplication, 'starts_at' => now(), 'ends_at' => null]],
            );
            self::fail('Synthetic failure did not escape.');
        } catch (DomainRuleViolation) {
            $this->assertDatabaseMissing('users', ['email' => 'rollback@example.test']);
            Notification::assertNothingSent();
        }
    }

    public function test_create_rolls_back_mutually_exempting_bounded_administrator_assignments(): void
    {
        Notification::fake();
        $actor = User::factory()->active()->create();
        $adminUsers = Permission::query()->where('code', 'admin.users')->firstOrFail();
        $adminRoles = Permission::query()->where('code', 'admin.roles')->firstOrFail();
        $roles = collect([
            Role::factory()->create(),
            Role::factory()->create(),
            Role::factory()->create(),
            Role::factory()->create(),
        ]);
        $roles->take(2)->each(fn (Role $role) => $role->permissions()->attach($adminUsers));
        $roles->skip(2)->each(fn (Role $role) => $role->permissions()->attach($adminRoles));
        $this->app->bind(
            AuthorizationService::class,
            fn () => $this->authorization(['admin.users', 'admin.roles']),
        );

        try {
            $this->app->make(CreateInvitedUser::class)->handle(
                $actor,
                ['name' => 'Bounded Admin', 'email' => 'bounded@example.test', 'timezone' => 'UTC'],
                null,
                null,
                'bounded-admin-create',
                $roles->map(static fn (Role $role): array => [
                    'role' => $role,
                    'application' => null,
                    'starts_at' => now(),
                    'ends_at' => now()->addDay(),
                ])->all(),
            );
            self::fail('Mutually exempting bounded administrator assignments were persisted.');
        } catch (DomainRuleViolation $exception) {
            self::assertSame('bounded_effective_administrator_assignment', $exception->ruleCode);
        }

        $this->assertDatabaseMissing('users', ['email' => 'bounded@example.test']);
        self::assertSame(0, RoleAssignment::query()->count());
        $this->assertDatabaseMissing('security_events', ['correlation_id' => 'bounded-admin-create']);
        Notification::assertNothingSent();
    }

    public function test_email_change_returns_user_to_invited_and_invalidates_authentication_state(): void
    {
        Notification::fake();
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->active()->create(['session_version' => 3]);
        AuthChallenge::query()->create([
            'user_id' => $target->id,
            'purpose' => 'LOGIN',
            'code_hmac' => str_repeat('a', 64),
            'expires_at' => now()->addMinute(),
        ]);
        AuthSession::query()->create([
            'session_id' => 'email-change-session',
            'user_id' => $target->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'user_session_version' => 3,
        ]);
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        $this->app->make(UpdateUser::class)->handle($actor, $target, [
            'employee_number' => 'E-9',
            'name' => 'Updated',
            'email' => ' Changed@Example.Test ',
            'timezone' => 'Indian/Mauritius',
        ], null, null, 'correlation');

        $target->refresh();
        self::assertSame('changed@example.test', $target->email);
        self::assertSame(UserState::Invited, $target->state);
        self::assertNull($target->email_verified_at);
        self::assertSame(4, $target->session_version);
        self::assertSame(0, AuthSession::query()->where('user_id', $target->id)->count());
        self::assertNotNull(AuthChallenge::query()->sole()->invalidated_at);
        Notification::assertSentTo($target, ActivationInvitationNotification::class);
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.user.email_changed']);
    }

    public function test_state_change_invalidates_sessions_and_records_event(): void
    {
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->active()->create(['session_version' => 2]);
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        $this->app->make(ChangeUserState::class)->handle(
            $actor,
            $target,
            UserState::Suspended,
            null,
            null,
            'correlation',
        );

        self::assertSame(UserState::Suspended, $target->refresh()->state);
        self::assertSame(3, $target->session_version);
        $this->assertDatabaseHas('security_events', [
            'event_code' => 'identity.user.state_changed',
            'subject_user_id' => $target->id,
        ]);
    }

    public function test_invited_user_cannot_be_activated_without_otp(): void
    {
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->invited()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(ChangeUserState::class)->handle(
            $actor,
            $target,
            UserState::Active,
            null,
            null,
            null,
        );
    }

    public function test_reactivating_a_deactivated_user_returns_them_to_invited_and_sends_notice_after_commit(): void
    {
        Notification::fake();
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->deactivated()->create(['email_verified_at' => null]);
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        $this->app->make(ChangeUserState::class)->handle(
            $actor,
            $target,
            UserState::Active,
            null,
            null,
            null,
        );

        self::assertSame(UserState::Invited, $target->refresh()->state);
        self::assertNotNull($target->invitation_expires_at);
        Notification::assertSentTo($target, ActivationInvitationNotification::class);
    }

    public function test_unactivated_user_cannot_become_active_through_an_intermediate_suspension(): void
    {
        Notification::fake();
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->invited()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        $action = $this->app->make(ChangeUserState::class);
        $action->handle($actor, $target, UserState::Suspended, null, null, null);
        $action->handle($actor, $target, UserState::Active, null, null, null);

        self::assertSame(UserState::Invited, $target->refresh()->state);
        self::assertNull($target->email_verified_at);
        self::assertNull($target->activated_at);
        Notification::assertSentTo($target, ActivationInvitationNotification::class);
    }

    public function test_deactivated_user_cannot_become_active_through_an_intermediate_suspension(): void
    {
        Notification::fake();
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->deactivated()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        $action = $this->app->make(ChangeUserState::class);
        $action->handle($actor, $target, UserState::Suspended, null, null, null);
        $action->handle($actor, $target, UserState::Active, null, null, null);

        self::assertSame(UserState::Invited, $target->refresh()->state);
        self::assertNull($target->email_verified_at);
        self::assertNull($target->activated_at);
        Notification::assertSentTo($target, ActivationInvitationNotification::class);
    }

    public function test_action_boundary_rejects_direct_transition_to_invited(): void
    {
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->active()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(ChangeUserState::class)->handle(
            $actor,
            $target,
            UserState::Invited,
            null,
            null,
            null,
        );
    }

    public function test_invitation_and_unlock_actions_reauthorize_the_locked_actor(): void
    {
        Notification::fake();
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $permission === 'admin.users'
                    && $requiresFreshReauthentication
                    && $user->state === UserState::Active;
            }
        });

        foreach ([ResendInvitation::class, RevokeInvitation::class, UnlockUser::class] as $actionClass) {
            $actor = User::factory()->active()->create();
            $target = $actionClass === UnlockUser::class
                ? User::factory()->locked()->create()
                : User::factory()->invited()->create();
            User::query()->whereKey($actor->id)->update(['state' => UserState::Suspended->value]);

            try {
                $this->app->make($actionClass)->handle($actor, $target, null, null, null);
                self::fail($actionClass.' trusted stale actor authorization.');
            } catch (AuthorizationException) {
                self::assertTrue(true);
            }
        }

        Notification::assertNothingSent();
    }

    public function test_administrative_session_revocation_requires_admin_users_even_for_self_target(): void
    {
        $actor = User::factory()->active()->create(['session_version' => 9]);
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization([]));

        try {
            $this->app->make(RevokeUserSessions::class)->handle($actor, $actor, null, null, null);
            self::fail('The administrative wrapper used the self-service authorization bypass.');
        } catch (AuthorizationException) {
            self::assertSame(9, $actor->refresh()->session_version);
        }
    }

    public function test_user_pages_are_authorized_paginated_and_mutations_use_a_safe_freshness_landing(): void
    {
        $this->withoutVite();
        $actor = User::factory()->active()->create();
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $permission === 'admin.users';
            }
        });
        $this->authenticateBrowser($actor, now()->subHour());
        $this->actingAs($actor);

        foreach (range(1, 16) as $index) {
            User::factory()->active()->create(['name' => sprintf('Person %02d', $index)]);
        }

        $this->get('/admin/users')->assertOk()->assertViewHas(
            'users',
            static fn (mixed $users): bool => $users instanceof LengthAwarePaginator
                && $users->perPage() === 15,
        );
        $this->post('/admin/users', [
            'name' => 'Blocked Person',
            'email' => 'blocked@example.test',
            'timezone' => 'UTC',
        ])->assertRedirect('/reauthenticate');
        self::assertSame('admin.users.index', session('identity.reauthentication_return_route'));
        $this->assertDatabaseMissing('users', ['email' => 'blocked@example.test']);
    }

    public function test_initial_assignment_scope_requires_exactly_one_active_application_for_application_scope(): void
    {
        $actor = User::factory()->active()->create();
        $role = Role::factory()->create();
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return in_array($permission, ['admin.users', 'admin.roles'], true);
            }
        });
        $this->authenticateBrowser($actor, now());
        $this->actingAs($actor);

        $this->from('/admin/users/create')->post('/admin/users', [
            'name' => 'Invalid Scope',
            'email' => 'invalid-scope@example.test',
            'timezone' => 'UTC',
            'assignments' => [[
                'role' => $role->public_id,
                'scope_type' => 'APPLICATION',
                'application' => '',
            ]],
        ])->assertRedirect('/admin/users/create')->assertSessionHasErrors('assignments.0.application');

        $this->assertDatabaseMissing('users', ['email' => 'invalid-scope@example.test']);
    }

    public function test_state_endpoint_rejects_direct_invitation_transitions(): void
    {
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->suspended()->create();
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $permission === 'admin.users';
            }
        });
        $this->authenticateBrowser($actor, now());
        $this->actingAs($actor);

        $this->from(route('admin.users.show', $target))
            ->patch(route('admin.users.state.update', $target), ['state' => UserState::Invited->value])
            ->assertRedirect(route('admin.users.show', $target))
            ->assertSessionHasErrors('state');

        self::assertSame(UserState::Suspended, $target->refresh()->state);
    }

    /** @param list<string> $allowed */
    private function authorization(array $allowed): AuthorizationService
    {
        return new class($allowed) implements AuthorizationService
        {
            /** @param list<string> $allowed */
            public function __construct(private readonly array $allowed) {}

            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return in_array($permission, $this->allowed, true) && $requiresFreshReauthentication;
            }
        };
    }

    private function authenticateBrowser(User $user, mixed $reauthenticatedAt): void
    {
        $session = $this->app->make(Session::class);
        $sessionId = str_pad((string) $user->id, 40, '5', STR_PAD_LEFT);
        $session->setId($sessionId);
        $this->withCookie((string) config('session.cookie'), $sessionId);
        AuthSession::query()->create([
            'session_id' => $sessionId,
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'mfa_authenticated_at' => now(),
            'reauthenticated_at' => $reauthenticatedAt,
            'user_session_version' => $user->session_version,
        ]);
    }
}
