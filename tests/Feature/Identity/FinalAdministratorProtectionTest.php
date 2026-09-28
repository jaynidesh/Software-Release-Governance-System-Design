<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Assignments\RevokeRoleAssignment;
use App\Application\Identity\Roles\ChangeRoleState;
use App\Application\Identity\Roles\SyncRolePermissions;
use App\Application\Identity\Users\ChangeUserState;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
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
}
