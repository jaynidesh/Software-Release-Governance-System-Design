<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\AuthorizationCatalog;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Models\Application;
use App\Models\AuthSession;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class AuthorizationBoundaryTest extends TestCase
{
    use RefreshDatabase;

    public function test_read_access_does_not_replace_fresh_reauthentication_for_mutation(): void
    {
        $this->withoutVite();
        $this->actAsApplicationAdministrator(reauthenticatedAt: null);

        $this->get('/admin/applications')->assertOk();
        $this->post('/admin/applications', [
            'code' => 'payments',
            'name' => 'Payments',
        ])->assertForbidden();

        $this->assertDatabaseMissing('applications', ['code' => 'payments']);
    }

    public function test_transactional_action_reauthorizes_after_the_form_request_boundary(): void
    {
        $user = User::factory()->active()->create();
        $this->actingAs($user);
        $authorization = new class implements AuthorizationService
        {
            public int $calls = 0;

            public function allows(
                User $user,
                string $permission,
                ?Application $application,
                bool $requiresFreshReauthentication,
            ): bool {
                $this->calls++;

                return $this->calls === 1;
            }
        };
        $this->app->instance(AuthorizationService::class, $authorization);

        $this->post('/admin/applications', [
            'code' => 'payments',
            'name' => 'Payments',
        ])->assertForbidden();

        self::assertSame(2, $authorization->calls);
        $this->assertDatabaseMissing('applications', ['code' => 'payments']);
    }

    public function test_navigation_link_is_a_usability_guard_not_an_authorization_substitute(): void
    {
        $this->withoutVite();
        $ordinaryUser = User::factory()->active()->create();
        $this->authenticate($ordinaryUser);
        $this->actingAs($ordinaryUser);

        $this->get('/')->assertOk()->assertDontSee('Applications');

        $administrator = $this->actAsApplicationAdministrator(reauthenticatedAt: now());
        self::assertNotSame($ordinaryUser->id, $administrator->id);

        $this->get('/')->assertOk()->assertSee('Applications');
    }

    public function test_unexpected_create_attributes_cannot_set_application_state(): void
    {
        $this->actAsApplicationAdministrator(reauthenticatedAt: now());

        $this->post('/admin/applications', [
            'code' => 'payments',
            'name' => 'Payments',
            'is_active' => false,
        ])->assertRedirect('/admin/applications');

        $this->assertDatabaseHas('applications', [
            'code' => 'payments',
            'is_active' => true,
        ]);
    }

    public function test_inactive_application_rejects_a_new_scoped_assignment(): void
    {
        $user = User::factory()->active()->create();
        $role = Role::factory()->create();
        $inactiveApplication = Application::factory()->inactive()->create();

        $this->expectException(DomainRuleViolation::class);
        $this->grantRole($user, $role, $inactiveApplication);
    }

    public function test_inactive_application_rejects_reactivating_a_revoked_scoped_assignment(): void
    {
        $user = User::factory()->active()->create();
        $role = Role::factory()->create();
        $application = Application::factory()->create();
        $assignment = RoleAssignment::factory()->revoked()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => $application->id,
        ]);
        $application->update(['is_active' => false]);

        $this->expectException(DomainRuleViolation::class);
        $assignment->update(['revoked_at' => null]);
    }

    public function test_inactive_application_rejects_changing_a_global_assignment_to_scoped(): void
    {
        $user = User::factory()->active()->create();
        $role = Role::factory()->create();
        $inactiveApplication = Application::factory()->inactive()->create();
        $assignment = RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
        ]);

        $this->expectException(DomainRuleViolation::class);
        $assignment->update(['application_id' => $inactiveApplication->id]);
    }

    private function actAsApplicationAdministrator(mixed $reauthenticatedAt): User
    {
        $user = User::factory()->active()->create();
        $this->grant($user, 'admin.applications');
        UserMfaMethod::query()->create([
            'user_id' => $user->id,
            'type' => MfaMethodType::Totp,
            'secret' => 'TESTONLYSHAREDSECRET',
            'confirmed_at' => now(),
        ]);
        $this->authenticate($user, now(), $reauthenticatedAt);
        $this->actingAs($user);

        return $user;
    }

    private function grant(User $user, string $permissionCode): RoleAssignment
    {
        $role = Role::factory()->create();
        $permission = Permission::query()->create([
            'code' => $permissionCode,
            'description' => 'Test permission.',
            'scope_type' => AuthorizationCatalog::permissions()[$permissionCode],
        ]);
        $role->permissions()->attach($permission);

        return RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
        ]);
    }

    private function grantRole(User $user, Role $role, Application $application): RoleAssignment
    {
        return RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => $application->id,
        ]);
    }

    private function authenticate(
        User $user,
        mixed $mfaAuthenticatedAt = null,
        mixed $reauthenticatedAt = null,
    ): AuthSession {
        $sessionId = str_pad((string) $user->id, 40, '0', STR_PAD_LEFT);
        $this->sessionStore()->setId($sessionId);
        $this->withCookie((string) config('session.cookie'), $sessionId);

        return AuthSession::query()->create([
            'session_id' => $sessionId,
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHours(8),
            'primary_authenticated_at' => now(),
            'mfa_authenticated_at' => $mfaAuthenticatedAt,
            'reauthenticated_at' => $reauthenticatedAt,
            'user_session_version' => $user->session_version,
        ]);
    }

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }
}
