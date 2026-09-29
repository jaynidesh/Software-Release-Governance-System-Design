<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Assignments\AssignRole;
use App\Application\Identity\Assignments\RevokeRoleAssignment;
use App\Contracts\Identity\AuthorizationService;
use App\Models\Application;
use App\Models\AuthSession;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Support\Exceptions\DomainRuleViolation;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class RoleAssignmentTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->seed(IdentityAuthorizationSeeder::class);
    }

    public function test_assignment_actions_require_admin_roles_with_fresh_proof_at_the_action_boundary(): void
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $role = Role::factory()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.users']));

        $this->expectException(AuthorizationException::class);

        $this->app->make(AssignRole::class)->handle($actor, $target, $role, null, now(), null, null, null, null);
    }

    public function test_assignment_denies_self_mutation_and_inactive_application_scope(): void
    {
        $actor = User::factory()->active()->create();
        $role = Role::factory()->create();
        $application = Application::factory()->inactive()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.roles']));

        try {
            $this->app->make(AssignRole::class)->handle(
                $actor,
                $actor,
                $role,
                null,
                now(),
                null,
                null,
                null,
                null,
            );
            self::fail('Self-assignment was accepted.');
        } catch (DomainRuleViolation $exception) {
            self::assertSame('self_role_assignment', $exception->ruleCode);
        }

        $target = User::factory()->active()->create();

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(AssignRole::class)->handle(
            $actor,
            $target,
            $role,
            $application,
            now(),
            null,
            null,
            null,
            null,
        );
    }

    public function test_global_effective_administrator_grant_must_start_now_and_never_expire(): void
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $role = Role::factory()->create();
        $role->permissions()->attach(Permission::query()
            ->whereIn('code', ['admin.users', 'admin.roles'])
            ->pluck('id'));
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.roles']));

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(AssignRole::class)->handle(
            $actor,
            $target,
            $role,
            null,
            now()->addMinute(),
            now()->addDay(),
            null,
            null,
            null,
        );
    }

    public function test_assignment_reactivation_is_durable_and_invalidates_target_sessions(): void
    {
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->active()->create(['session_version' => 7]);
        $role = Role::factory()->create();
        $assignment = RoleAssignment::factory()->revoked()->create([
            'user_id' => $target->id,
            'role_id' => $role->id,
        ]);
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.roles']));

        $result = $this->app->make(AssignRole::class)->handle(
            $actor,
            $target,
            $role,
            null,
            now(),
            null,
            '127.0.0.1',
            'Test',
            'correlation',
        );

        self::assertTrue($result->is($assignment));
        self::assertNull($result->revoked_at);
        self::assertSame(8, $target->refresh()->session_version);
        $this->assertDatabaseHas('security_events', [
            'event_code' => 'identity.role_assignment.assigned',
            'actor_id' => $actor->id,
            'subject_user_id' => $target->id,
        ]);

        $this->app->make(RevokeRoleAssignment::class)->handle(
            $actor,
            $result,
            '127.0.0.1',
            'Test',
            'correlation',
        );
        self::assertNotNull($result->refresh()->revoked_at);
        self::assertSame(9, $target->refresh()->session_version);
    }

    public function test_assignment_http_mutation_has_its_own_roles_authorization_and_freshness_boundary(): void
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $role = Role::factory()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->authorization(['admin.roles']));
        $session = $this->app->make(Session::class);
        $sessionId = str_pad((string) $actor->id, 40, '7', STR_PAD_LEFT);
        $session->setId($sessionId);
        $this->withCookie((string) config('session.cookie'), $sessionId);
        AuthSession::query()->create([
            'session_id' => $sessionId,
            'user_id' => $actor->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'mfa_authenticated_at' => now(),
            'reauthenticated_at' => now()->subHour(),
            'user_session_version' => $actor->session_version,
        ]);
        $this->actingAs($actor);

        $this->post('/admin/users/'.$target->public_id.'/role-assignments', [
            'role' => $role->public_id,
            'scope_type' => 'GLOBAL',
            'starts_at' => now()->toAtomString(),
        ])->assertRedirect('/reauthenticate');
        self::assertSame('admin.role-assignments.index', session('identity.reauthentication_return_route'));
        self::assertSame(0, RoleAssignment::query()->where('user_id', $target->id)->count());
    }

    public function test_role_only_administrator_has_a_focused_assignment_surface_and_safe_reauthentication_return(): void
    {
        $this->withoutVite();
        $actor = User::factory()->active()->create();
        $protector = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $protector->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $target = User::factory()->active()->create();
        $role = Role::factory()->create();
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $permission === 'admin.roles';
            }
        });
        $session = $this->app->make(Session::class);
        $sessionId = str_pad((string) $actor->id, 40, '9', STR_PAD_LEFT);
        $session->setId($sessionId);
        $this->withCookie((string) config('session.cookie'), $sessionId);
        $authSession = AuthSession::query()->create([
            'session_id' => $sessionId,
            'user_id' => $actor->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'mfa_authenticated_at' => now(),
            'reauthenticated_at' => now()->subHour(),
            'user_session_version' => $actor->session_version,
        ]);
        $this->actingAs($actor);

        $this->get('/admin/role-assignments')
            ->assertOk()
            ->assertSee($target->name)
            ->assertDontSee($target->email);
        $this->post('/admin/users/'.$target->public_id.'/role-assignments', [
            'role' => $role->public_id,
            'scope_type' => 'GLOBAL',
        ])->assertRedirect('/reauthenticate');
        self::assertSame('admin.role-assignments.index', session('identity.reauthentication_return_route'));

        $authSession->forceFill(['reauthenticated_at' => now()])->save();
        $this->post('/admin/users/'.$target->public_id.'/role-assignments', [
            'role' => $role->public_id,
            'scope_type' => 'GLOBAL',
        ])->assertRedirect();
        $this->assertDatabaseHas('role_assignments', [
            'user_id' => $target->id,
            'role_id' => $role->id,
        ]);
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
}
