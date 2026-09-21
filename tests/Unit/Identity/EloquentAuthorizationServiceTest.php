<?php

declare(strict_types=1);

namespace Tests\Unit\Identity;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\AuthorizationCatalog;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\AuthSession;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Services\Identity\EloquentAuthorizationService;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class EloquentAuthorizationServiceTest extends TestCase
{
    use RefreshDatabase;

    public function test_authorization_contract_is_bound_in_the_container(): void
    {
        self::assertTrue($this->app->bound(AuthorizationService::class));
        self::assertInstanceOf(
            EloquentAuthorizationService::class,
            $this->app->make(AuthorizationService::class),
        );
    }

    public function test_current_global_assignment_grants_a_global_permission(): void
    {
        $user = User::factory()->active()->create();
        $this->grant($user, 'admin.applications');
        $this->authenticate($user, mfaAuthenticatedAt: now(), reauthenticatedAt: now());
        $this->confirmMfa($user);

        self::assertTrue($this->service()->allows($user, 'admin.applications', null, true));
    }

    #[DataProvider('inactiveUserStates')]
    public function test_inactive_users_are_denied(UserState $state): void
    {
        $user = User::factory()->active()->create(['state' => $state]);
        $this->grant($user, 'release.view');
        $application = Application::factory()->create();
        $this->authenticate($user);

        self::assertFalse($this->service()->allows($user, 'release.view', $application, false));
    }

    /** @return array<string, array{UserState}> */
    public static function inactiveUserStates(): array
    {
        return [
            'invited' => [UserState::Invited],
            'suspended' => [UserState::Suspended],
            'deactivated' => [UserState::Deactivated],
        ];
    }

    public function test_inactive_roles_are_denied(): void
    {
        $user = User::factory()->active()->create();
        $application = Application::factory()->create();
        $this->grant($user, 'release.view', roleAttributes: ['is_active' => false]);
        $this->authenticate($user);

        self::assertFalse($this->service()->allows($user, 'release.view', $application, false));
    }

    #[DataProvider('nonCurrentAssignmentAttributes')]
    public function test_non_current_assignments_are_denied(array $assignmentAttributes): void
    {
        $user = User::factory()->active()->create();
        $application = Application::factory()->create();
        $this->grant($user, 'release.view', assignmentAttributes: $assignmentAttributes);
        $this->authenticate($user);

        self::assertFalse($this->service()->allows($user, 'release.view', $application, false));
    }

    /** @return array<string, array{array<string, string>}> */
    public static function nonCurrentAssignmentAttributes(): array
    {
        return [
            'future' => [['starts_at' => '+1 hour']],
            'expired' => [['ends_at' => '-1 second']],
            'revoked' => [['revoked_at' => 'now']],
        ];
    }

    public function test_global_application_permission_grants_every_active_application(): void
    {
        $user = User::factory()->active()->create();
        $firstApplication = Application::factory()->create();
        $secondApplication = Application::factory()->create();
        $this->grant($user, 'release.view');
        $this->authenticate($user);

        self::assertTrue($this->service()->allows($user, 'release.view', $firstApplication, false));
        self::assertTrue($this->service()->allows($user, 'release.view', $secondApplication, false));
    }

    public function test_application_assignment_is_limited_to_the_same_active_application(): void
    {
        $user = User::factory()->active()->create();
        $assignedApplication = Application::factory()->create();
        $otherApplication = Application::factory()->create();
        $this->grant($user, 'release.view', $assignedApplication);
        $this->authenticate($user);

        self::assertTrue($this->service()->allows($user, 'release.view', $assignedApplication, false));
        self::assertFalse($this->service()->allows($user, 'release.view', $otherApplication, false));
    }

    public function test_application_assignment_does_not_grant_global_permissions(): void
    {
        $user = User::factory()->active()->create();
        $application = Application::factory()->create();
        $this->grant($user, 'admin.applications', $application);
        $this->authenticate($user, mfaAuthenticatedAt: now(), reauthenticatedAt: now());
        $this->confirmMfa($user);

        self::assertFalse($this->service()->allows($user, 'admin.applications', null, true));
    }

    public function test_inactive_applications_are_denied_for_global_and_scoped_grants(): void
    {
        $globallyAssignedUser = User::factory()->active()->create();
        $scopedUser = User::factory()->active()->create();
        $inactiveApplication = Application::factory()->create();
        $this->grant($globallyAssignedUser, 'release.view');
        $this->grant($scopedUser, 'release.view', $inactiveApplication);
        $inactiveApplication->update(['is_active' => false]);

        $this->authenticate($globallyAssignedUser);
        self::assertFalse($this->service()->allows(
            $globallyAssignedUser,
            'release.view',
            $inactiveApplication,
            false,
        ));

        $this->authenticate($scopedUser);
        self::assertFalse($this->service()->allows($scopedUser, 'release.view', $inactiveApplication, false));
    }

    public function test_privileged_permission_requires_confirmed_mfa_and_an_mfa_authenticated_session(): void
    {
        $user = User::factory()->active()->create();
        $this->grant($user, 'admin.applications');
        $this->authenticate($user, reauthenticatedAt: now());

        self::assertFalse($this->service()->allows($user, 'admin.applications', null, false));

        $method = UserMfaMethod::query()->create([
            'user_id' => $user->id,
            'type' => MfaMethodType::Totp,
            'secret' => 'TESTONLYSHAREDSECRET',
        ]);
        self::assertFalse($this->service()->allows($user, 'admin.applications', null, false));

        $method->update(['confirmed_at' => now()]);
        AuthSession::query()->where('session_id', $this->sessionStore()->getId())
            ->update(['mfa_authenticated_at' => now()]);

        self::assertTrue($this->service()->allows($user, 'admin.applications', null, false));
    }

    public function test_fresh_reauthentication_is_required_only_when_requested(): void
    {
        $user = User::factory()->active()->create();
        $this->grant($user, 'admin.applications');
        $this->confirmMfa($user);
        $this->authenticate($user, mfaAuthenticatedAt: now());

        self::assertTrue($this->service()->allows($user, 'admin.applications', null, false));
        self::assertFalse($this->service()->allows($user, 'admin.applications', null, true));

        AuthSession::query()->where('session_id', $this->sessionStore()->getId())->update([
            'reauthenticated_at' => now()->subMinutes((int) config('identity.privileged_reauth_minutes'))->subSecond(),
        ]);
        self::assertFalse($this->service()->allows($user, 'admin.applications', null, true));

        AuthSession::query()->where('session_id', $this->sessionStore()->getId())->update([
            'reauthenticated_at' => now(),
        ]);
        self::assertTrue($this->service()->allows($user, 'admin.applications', null, true));
    }

    public function test_invalid_current_session_metadata_is_denied(): void
    {
        $user = User::factory()->active()->create();
        $application = Application::factory()->create();
        $this->grant($user, 'release.view');

        self::assertFalse($this->service()->allows($user, 'release.view', $application, false));

        $session = $this->authenticate($user);
        $session->update(['revoked_at' => now()]);
        self::assertFalse($this->service()->allows($user, 'release.view', $application, false));

        $session->update(['revoked_at' => null, 'last_seen_at' => now()->subHours(2)]);
        self::assertFalse($this->service()->allows($user, 'release.view', $application, false));

        $session->update([
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->subSecond(),
        ]);
        self::assertFalse($this->service()->allows($user, 'release.view', $application, false));

        $session->update([
            'absolute_expires_at' => now()->addHour(),
            'user_session_version' => $user->session_version + 1,
        ]);
        self::assertFalse($this->service()->allows($user, 'release.view', $application, false));
    }

    public function test_unknown_permissions_and_missing_application_scope_are_denied(): void
    {
        $user = User::factory()->active()->create();
        $this->grant($user, 'release.view');
        $this->authenticate($user);

        self::assertFalse($this->service()->allows($user, 'unknown.permission', null, false));
        self::assertFalse($this->service()->allows($user, 'release.view', null, false));
    }

    public function test_every_canonical_permission_is_registered_as_a_gate(): void
    {
        foreach (array_keys(AuthorizationCatalog::permissions()) as $permission) {
            self::assertTrue(Gate::has($permission), sprintf('Gate [%s] was not registered.', $permission));
        }
    }

    public function test_canonical_gate_delegates_with_application_scope(): void
    {
        $user = User::factory()->active()->create();
        $assignedApplication = Application::factory()->create();
        $otherApplication = Application::factory()->create();
        $this->grant($user, 'release.view', $assignedApplication);
        $this->authenticate($user);

        self::assertTrue(Gate::forUser($user)->allows('release.view', $assignedApplication));
        self::assertFalse(Gate::forUser($user)->allows('release.view', $otherApplication));
    }

    public function test_non_production_environment_prevents_lazy_loading(): void
    {
        self::assertTrue(Model::preventsLazyLoading());
    }

    private function service(): AuthorizationService
    {
        return $this->app->make(AuthorizationService::class);
    }

    /** @param array<string, mixed> $roleAttributes
     * @param  array<string, string>  $assignmentAttributes
     */
    private function grant(
        User $user,
        string $permissionCode,
        ?Application $application = null,
        array $roleAttributes = [],
        array $assignmentAttributes = [],
    ): RoleAssignment {
        $role = Role::factory()->create($roleAttributes);
        $permission = Permission::query()->firstOrCreate(
            ['code' => $permissionCode],
            [
                'description' => 'Test permission.',
                'scope_type' => AuthorizationCatalog::permissions()[$permissionCode],
            ],
        );
        $role->permissions()->attach($permission);

        $attributes = [
            'starts_at' => now()->subMinute(),
            'ends_at' => null,
            'revoked_at' => null,
        ];

        foreach ($assignmentAttributes as $key => $value) {
            $attributes[$key] = $value === 'now' ? now() : now()->modify($value);
        }

        $assignment = RoleAssignment::factory()
            ->for($user)
            ->for($role);

        if ($application !== null) {
            $assignment = $assignment->for($application);
        }

        return $assignment->create($attributes);
    }

    private function authenticate(
        User $user,
        mixed $mfaAuthenticatedAt = null,
        mixed $reauthenticatedAt = null,
    ): AuthSession {
        $this->sessionStore()->setId('session-'.$user->id);

        return AuthSession::query()->create([
            'session_id' => $this->sessionStore()->getId(),
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

    private function confirmMfa(User $user): UserMfaMethod
    {
        return UserMfaMethod::query()->create([
            'user_id' => $user->id,
            'type' => MfaMethodType::Totp,
            'secret' => 'TESTONLYSHAREDSECRET',
            'confirmed_at' => now(),
        ]);
    }

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }
}
