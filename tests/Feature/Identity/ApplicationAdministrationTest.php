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
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Foundation\Application as ApplicationContract;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class ApplicationAdministrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_guest_is_redirected_from_application_administration(): void
    {
        $this->get('/admin/applications')->assertRedirect('/');
    }

    public function test_authenticated_user_without_admin_applications_is_forbidden(): void
    {
        $user = User::factory()->active()->create();
        $this->authenticate($user);
        $this->actingAs($user);

        $this->get('/admin/applications')->assertForbidden();
    }

    public function test_authorized_administrator_sees_deterministically_paginated_applications(): void
    {
        $this->withoutVite();
        $this->actAsApplicationAdministrator();
        Application::factory()->create(['code' => 'zulu', 'name' => 'Zulu']);
        Application::factory()->create(['code' => 'alpha', 'name' => 'Alpha']);
        Application::factory()->create(['code' => 'zzz', 'name' => 'Zzz']);

        foreach (range(1, 13) as $index) {
            Application::factory()->create([
                'code' => sprintf('middle-%02d', $index),
                'name' => sprintf('Middle %02d', $index),
            ]);
        }

        $this->get('/admin/applications')
            ->assertOk()
            ->assertSeeInOrder(['Alpha', 'Zulu'])
            ->assertViewHas('applications', static function (mixed $applications): bool {
                return $applications instanceof LengthAwarePaginator
                    && $applications->perPage() === 15
                    && $applications->total() === 16;
            });
    }

    public function test_authorized_administrator_creates_an_application_with_normalized_values(): void
    {
        $this->actAsApplicationAdministrator();

        $this->post('/admin/applications', [
            'code' => '  PAYMENTS_API  ',
            'name' => '  Payments API  ',
        ])->assertRedirect('/admin/applications');

        $this->assertDatabaseHas('applications', [
            'code' => 'payments_api',
            'name' => 'Payments API',
            'is_active' => true,
        ]);
    }

    public function test_normalized_duplicate_application_code_is_rejected(): void
    {
        Application::factory()->create(['code' => 'payments_api', 'name' => 'Existing Payments']);
        $this->actAsApplicationAdministrator();

        $this->from('/admin/applications/create')->post('/admin/applications', [
            'code' => '  PAYMENTS_API  ',
            'name' => 'New Payments',
        ])->assertRedirect('/admin/applications/create')->assertSessionHasErrors('code');

        self::assertSame(1, Application::query()->count());
    }

    public function test_application_routes_bind_only_public_ulids(): void
    {
        $this->withoutVite();
        $application = Application::factory()->create();
        $this->actAsApplicationAdministrator();

        $this->get('/admin/applications/'.$application->public_id.'/edit')->assertOk();
        $this->get('/admin/applications/'.$application->id.'/edit')->assertNotFound();
    }

    public function test_authorized_administrator_renames_an_application_without_changing_its_code(): void
    {
        $application = Application::factory()->create(['code' => 'payments', 'name' => 'Payments']);
        $this->actAsApplicationAdministrator();

        $this->patch('/admin/applications/'.$application->public_id, [
            'name' => 'Payments Platform',
            'code' => 'attempted-change',
        ])->assertRedirect('/admin/applications');

        $this->assertDatabaseHas('applications', [
            'id' => $application->id,
            'code' => 'payments',
            'name' => 'Payments Platform',
        ]);
    }

    public function test_deactivation_retains_assignments_and_immediately_denies_business_authorization(): void
    {
        $application = Application::factory()->create();
        $businessUser = User::factory()->active()->create();
        $assignment = $this->grant($businessUser, 'release.view', $application);
        $this->actAsApplicationAdministrator();

        $this->patch('/admin/applications/'.$application->public_id.'/state', [
            'is_active' => false,
        ])->assertRedirect('/admin/applications');

        $this->assertDatabaseHas('applications', ['id' => $application->id, 'is_active' => false]);
        $this->assertModelExists($assignment);

        $this->authenticate($businessUser);
        self::assertFalse($this->app->make(AuthorizationService::class)->allows(
            $businessUser,
            'release.view',
            $application,
            false,
        ));
    }

    public function test_application_mutation_rejects_missing_csrf_token(): void
    {
        $this->app->bind(
            PreventRequestForgery::class,
            static fn (ApplicationContract $app): PreventRequestForgery => new class($app, $app->make(Encrypter::class)) extends PreventRequestForgery
            {
                protected function runningUnitTests(): bool
                {
                    return false;
                }
            },
        );
        $this->actAsApplicationAdministrator();

        $this->post('/admin/applications', [
            'code' => 'payments',
            'name' => 'Payments',
        ])->assertStatus(419);

        $this->assertDatabaseMissing('applications', ['code' => 'payments']);
    }

    private function actAsApplicationAdministrator(): User
    {
        $user = User::factory()->active()->create();
        $this->grant($user, 'admin.applications');
        UserMfaMethod::query()->create([
            'user_id' => $user->id,
            'type' => MfaMethodType::Totp,
            'secret' => 'TESTONLYSHAREDSECRET',
            'confirmed_at' => now(),
        ]);
        $this->authenticate($user, now(), now());
        $this->actingAs($user);

        return $user;
    }

    private function grant(
        User $user,
        string $permissionCode,
        ?Application $application = null,
    ): RoleAssignment {
        $role = Role::factory()->create();
        $permission = Permission::query()->firstOrCreate(
            ['code' => $permissionCode],
            [
                'description' => 'Test permission.',
                'scope_type' => AuthorizationCatalog::permissions()[$permissionCode],
            ],
        );
        $role->permissions()->attach($permission);

        return RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => $application?->id,
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
