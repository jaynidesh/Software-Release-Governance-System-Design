<?php

declare(strict_types=1);

namespace Tests\Unit\Identity;

use App\Domain\Identity\Enums\PermissionScope;
use App\Models\Application;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Services\Identity\PrivilegedPermissionResolver;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class PrivilegedPermissionResolverTest extends TestCase
{
    use RefreshDatabase;

    public function test_mandatory_baseline_cannot_be_removed_by_configuration(): void
    {
        config()->set('identity.privileged_permissions', ['custom.deploy', 'sensitive.']);
        $resolver = $this->app->make(PrivilegedPermissionResolver::class);

        self::assertTrue($resolver->isPrivileged('admin.users'));
        self::assertTrue($resolver->isPrivileged('production.approve'));
        self::assertTrue($resolver->isPrivileged('signoff.production'));
        self::assertTrue($resolver->isPrivileged('maker_checker.override.approve'));
        self::assertTrue($resolver->isPrivileged('custom.deploy'));
        self::assertTrue($resolver->isPrivileged('sensitive.rotate'));
        self::assertFalse($resolver->isPrivileged('production.deploy'));
    }

    public function test_current_database_grants_determine_privilege(): void
    {
        $user = User::factory()->active()->create();
        $application = Application::factory()->create(['is_active' => true]);
        $role = Role::factory()->create(['is_active' => true]);
        $permission = Permission::factory()->create([
            'code' => 'production.approve',
            'scope_type' => PermissionScope::Application,
        ]);
        $role->permissions()->attach($permission);
        $assignment = RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => $application->id,
            'starts_at' => now()->subMinute(),
        ]);
        $resolver = $this->app->make(PrivilegedPermissionResolver::class);

        self::assertTrue($resolver->userIsPrivileged($user));

        $application->update(['is_active' => false]);
        self::assertFalse($resolver->userIsPrivileged($user));

        $application->update(['is_active' => true]);
        $assignment->update(['revoked_at' => now()]);
        self::assertFalse($resolver->userIsPrivileged($user));
    }

    public function test_global_permissions_do_not_flow_from_application_scoped_assignments(): void
    {
        $user = User::factory()->active()->create();
        $application = Application::factory()->create(['is_active' => true]);
        $role = Role::factory()->create(['is_active' => true]);
        $permission = Permission::factory()->create([
            'code' => 'admin.users',
            'scope_type' => PermissionScope::Global,
        ]);
        $role->permissions()->attach($permission);
        RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => $application->id,
        ]);

        self::assertFalse($this->app->make(PrivilegedPermissionResolver::class)->userIsPrivileged($user));
    }

    public function test_global_assignment_of_application_permission_requires_an_active_application(): void
    {
        $user = User::factory()->active()->create();
        $role = Role::factory()->create(['is_active' => true]);
        $permission = Permission::factory()->create([
            'code' => 'production.approve',
            'scope_type' => PermissionScope::Application,
        ]);
        $role->permissions()->attach($permission);
        RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => null,
        ]);
        $resolver = $this->app->make(PrivilegedPermissionResolver::class);

        self::assertFalse($resolver->userIsPrivileged($user));

        Application::factory()->create(['is_active' => true]);

        self::assertTrue($resolver->userIsPrivileged($user));
    }
}
