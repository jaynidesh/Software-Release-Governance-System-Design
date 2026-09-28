<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Roles\ChangeRoleState;
use App\Application\Identity\Roles\CreateRole;
use App\Application\Identity\Roles\SyncRolePermissions;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\PermissionScope;
use App\Models\Application;
use App\Models\AuthSession;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Support\Exceptions\DomainRuleViolation;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class RoleAdministrationTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->seed(IdentityAuthorizationSeeder::class);
    }

    public function test_role_codes_are_normalized_and_permissions_must_be_canonical(): void
    {
        $actor = User::factory()->active()->create();
        $this->allowRoles();

        $role = $this->app->make(CreateRole::class)->handle($actor, [
            'code' => '  Release_Operators  ',
            'name' => ' Release Operators ',
            'description' => ' Operators ',
        ], null, null, null);

        self::assertSame('release_operators', $role->code);
        self::assertSame('Release Operators', $role->name);

        $permission = Permission::query()->create([
            'code' => 'invented.permission',
            'description' => 'Not canonical.',
            'scope_type' => PermissionScope::Application,
        ]);

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(SyncRolePermissions::class)->handle(
            $actor,
            $role,
            [$permission->id],
            null,
            null,
            null,
        );
    }

    public function test_administrator_admin_bundle_is_immutable(): void
    {
        $this->seed();
        $actor = User::factory()->active()->create();
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        $kept = $administrator->permissions()->where('code', 'dashboard.view')->pluck('permissions.id')->all();
        $this->allowRoles();

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(SyncRolePermissions::class)->handle(
            $actor,
            $administrator,
            $kept,
            null,
            null,
            null,
        );
    }

    public function test_actor_cannot_edit_permissions_of_a_role_currently_assigned_to_them(): void
    {
        $actor = User::factory()->active()->create();
        $role = Role::factory()->create();
        RoleAssignment::factory()->create(['user_id' => $actor->id, 'role_id' => $role->id]);
        $this->allowRoles();

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(SyncRolePermissions::class)->handle($actor, $role, [], null, null, null);
    }

    public function test_system_roles_cannot_be_deleted_but_non_administrator_system_roles_can_be_deactivated(): void
    {
        $actor = User::factory()->active()->create();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => Role::query()->where('code', 'administrator')->firstOrFail()->id,
        ]);
        $role = Role::factory()->create(['is_system' => true, 'is_active' => true]);
        $this->allowRoles();

        $this->app->make(ChangeRoleState::class)->handle($actor, $role, false, null, null, null);
        self::assertFalse($role->refresh()->is_active);

        $this->expectException(\LogicException::class);
        $role->delete();
    }

    public function test_role_pages_are_readable_but_role_mutations_require_fresh_reauthentication(): void
    {
        $this->withoutVite();
        $actor = User::factory()->active()->create();
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $permission === 'admin.roles';
            }
        });
        $session = $this->app->make(Session::class);
        $sessionId = str_pad((string) $actor->id, 40, '6', STR_PAD_LEFT);
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

        $this->get('/admin/roles')->assertOk();
        $this->post('/admin/roles', [
            'code' => 'blocked',
            'name' => 'Blocked',
        ])->assertRedirect('/reauthenticate');
        self::assertSame('admin.roles.index', session('identity.reauthentication_return_route'));
        $this->assertDatabaseMissing('roles', ['code' => 'blocked']);
    }

    private function allowRoles(): void
    {
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $permission === 'admin.roles' && $requiresFreshReauthentication;
            }
        });
    }
}
