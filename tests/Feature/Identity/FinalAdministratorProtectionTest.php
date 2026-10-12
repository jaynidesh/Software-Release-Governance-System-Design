<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Assignments\AssignRole;
use App\Application\Identity\Assignments\RevokeRoleAssignment;
use App\Application\Identity\Roles\ChangeRoleState;
use App\Application\Identity\Roles\SyncRolePermissions;
use App\Application\Identity\Users\ChangeUserState;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Support\Exceptions\DomainRuleViolation;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class FinalAdministratorProtectionTest extends TestCase
{
    use RefreshDatabase;

    public function test_role_changes_cannot_promote_bounded_assignments_into_administrator_unions(): void
    {
        $actor = User::factory()->active()->create();
        $permanent = User::factory()->privileged()->create();
        $target = User::factory()->active()->create();
        $usersPermission = Permission::query()->where('code', 'admin.users')->value('id');
        $rolesPermission = Permission::query()->where('code', 'admin.roles')->value('id');

        foreach (['composition', 'activation', 'split_composition', 'split_activation'] as $path) {
            $role = Role::factory()->create(['is_active' => ! str_contains($path, 'activation')]);
            $assignment = RoleAssignment::factory()->create([
                'user_id' => $target->id, 'role_id' => $role->id, 'ends_at' => now()->addMinute(),
            ]);
            $permissions = [$usersPermission, $rolesPermission];
            $split = null;
            if (str_starts_with($path, 'split')) {
                $split = Role::factory()->create();
                $split->permissions()->attach($usersPermission);
                RoleAssignment::factory()->create(['user_id' => $target->id, 'role_id' => $split->id]);
                $permissions = [$rolesPermission];
            }
            if (str_contains($path, 'activation')) {
                $role->permissions()->sync($permissions);
            }
            $version = $target->refresh()->session_version;
            try {
                str_contains($path, 'activation')
                    ? $this->app->make(ChangeRoleState::class)->handle($actor, $role, true, null, null, 'bounded-role')
                    : $this->app->make(SyncRolePermissions::class)->handle($actor, $role, $permissions, null, null, 'bounded-role');
                self::fail('Role change promoted a bounded administrator: '.$path);
            } catch (DomainRuleViolation $exception) {
                self::assertSame('bounded_effective_administrator_assignment', $exception->ruleCode);
            }
            self::assertSame($version, $target->refresh()->session_version);
            self::assertSame(! str_contains($path, 'activation'), $role->refresh()->is_active);
            if (! str_contains($path, 'activation')) {
                self::assertSame(0, $role->permissions()->count());
            }
            $assignment->update(['revoked_at' => now()]);
            $split?->update(['is_active' => false]);
        }

        $this->travel(2)->minutes();
        try {
            $this->app->make(ChangeUserState::class)->handle($actor, $permanent, UserState::Deactivated, null, null, 'last-admin');
            self::fail('The permanent administrator was lost.');
        } catch (DomainRuleViolation $exception) {
            self::assertSame('last_effective_administrator', $exception->ruleCode);
        }
        self::assertSame(UserState::Active, $permanent->refresh()->state);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->seed(IdentityAuthorizationSeeder::class);
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $requiresFreshReauthentication && in_array($permission, ['admin.users', 'admin.roles'], true);
            }
        });
    }

    public function test_last_effective_administrator_cannot_be_lost_by_user_assignment_role_or_permission_changes(): void
    {
        $actor = User::factory()->active()->create();
        $last = User::factory()->active()->create();
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        $assignment = RoleAssignment::factory()->create([
            'user_id' => $last->id,
            'role_id' => $administrator->id,
        ]);

        foreach ([
            fn () => $this->app->make(ChangeUserState::class)->handle($actor, $last, UserState::Deactivated, null, null, null),
            fn () => $this->app->make(RevokeRoleAssignment::class)->handle($actor, $assignment, null, null, null),
            fn () => $this->app->make(ChangeRoleState::class)->handle($actor, $administrator, false, null, null, null),
            fn () => $this->app->make(SyncRolePermissions::class)->handle($actor, $administrator, [], null, null, null),
        ] as $mutation) {
            try {
                $mutation();
                self::fail('The final effective administrator was lost.');
            } catch (DomainRuleViolation $exception) {
                self::assertContains($exception->ruleCode, ['last_effective_administrator', 'administrator_permissions_immutable']);
            }
        }

        self::assertSame(UserState::Active, $last->refresh()->state);
        self::assertNull($assignment->refresh()->revoked_at);
        self::assertTrue($administrator->refresh()->is_active);
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.administrator.last_protected']);
    }

    public function test_reassigning_one_half_of_a_split_administrator_to_the_future_is_rolled_back(): void
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $usersRole = Role::factory()->create();
        $rolesRole = Role::factory()->create();
        $usersRole->permissions()->attach(Permission::query()->where('code', 'admin.users')->value('id'));
        $rolesRole->permissions()->attach(Permission::query()->where('code', 'admin.roles')->value('id'));
        RoleAssignment::factory()->create(['user_id' => $target->id, 'role_id' => $usersRole->id]);
        $assignment = RoleAssignment::factory()->create(['user_id' => $target->id, 'role_id' => $rolesRole->id]);
        $originalStart = $assignment->starts_at;

        try {
            $this->app->make(AssignRole::class)->handle(
                $actor,
                $target,
                $rolesRole,
                null,
                now()->addHour(),
                null,
                null,
                null,
                null,
            );
            self::fail('The final split-role administrator was rescheduled.');
        } catch (DomainRuleViolation $exception) {
            self::assertContains($exception->ruleCode, [
                'bounded_effective_administrator_assignment',
                'last_effective_administrator',
            ]);
        }

        self::assertTrue($assignment->refresh()->starts_at->equalTo($originalStart));
    }

    public function test_unactivated_active_record_does_not_satisfy_the_effective_administrator_invariant(): void
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $unactivated = User::factory()->active()->create([
            'email_verified_at' => null,
            'activated_at' => null,
        ]);
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        RoleAssignment::factory()->create(['user_id' => $target->id, 'role_id' => $administrator->id]);
        RoleAssignment::factory()->create(['user_id' => $unactivated->id, 'role_id' => $administrator->id]);

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(ChangeUserState::class)->handle(
            $actor,
            $target,
            UserState::Deactivated,
            null,
            null,
            null,
        );
    }
}
