<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Assignments\AssignRole;
use App\Application\Identity\Roles\ChangeRoleState;
use App\Application\Identity\Roles\SyncRolePermissions;
use App\Models\AuthSession;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Support\Exceptions\DomainRuleViolation;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Tests\TestCase;

final class MutationDenialEventsTest extends TestCase
{
    use DatabaseMigrations { runDatabaseMigrations as private frameworkRunDatabaseMigrations; }

    public function runDatabaseMigrations(): void
    {
        if (DB::getDriverName() === 'sqlite') {
            // These commit-boundary tests use a fresh in-memory database; historical
            // MySQL cutover down migrations are not a supported SQLite rollback.
            $this->refreshTestDatabase();
            $this->beforeApplicationDestroyed(static function (): void {
                RefreshDatabaseState::$migrated = false;
            });

            return;
        }
        $this->frameworkRunDatabaseMigrations();
    }

    public function test_direct_self_mutations_record_one_correlated_event_after_outer_rollback(): void
    {
        $this->seed(IdentityAuthorizationSeeder::class);
        $actor = User::factory()->active()->mfaConfirmed()->create();
        $admin = Role::query()->where('code', 'administrator')->sole();
        RoleAssignment::factory()->create(['user_id' => $actor->id, 'role_id' => $admin->id]);
        $this->authenticate($actor);
        $role = Role::factory()->create(['is_active' => false]);
        $role->permissions()->sync($admin->permissions()->pluck('permissions.id'));
        RoleAssignment::factory()->create(['user_id' => $actor->id, 'role_id' => $role->id]);

        foreach ([
            fn () => $this->app->make(AssignRole::class)->handle($actor, $actor, $admin, null, now(), null, null, null, 'self-denial'),
            fn () => $this->app->make(SyncRolePermissions::class)->handle($actor, $admin, [], null, null, 'self-denial'),
            fn () => $this->app->make(ChangeRoleState::class)->handle($actor, $role, true, null, null, 'self-denial'),
        ] as $index => $mutation) {
            DB::beginTransaction();
            try {
                $mutation();
                self::fail('Self mutation was accepted.');
            } catch (DomainRuleViolation) {
                DB::rollBack();
            }
            self::assertSame($index + 1, SecurityEvent::query()->where('event_code', 'identity.self_escalation.rejected')->count());
        }
        self::assertSame(3, SecurityEvent::query()->where('correlation_id', 'self-denial')->count());
    }

    public function test_denied_http_and_direct_mutations_are_audited_once_but_presentation_checks_are_not(): void
    {
        $this->seed(IdentityAuthorizationSeeder::class);
        $actor = User::factory()->active()->mfaConfirmed()->create();
        $target = User::factory()->active()->create();
        $role = Role::query()->where('code', 'administrator')->sole();
        $this->authenticate($actor);
        self::assertFalse(Gate::allows('admin.roles'));
        self::assertSame(0, SecurityEvent::query()->count());

        try {
            $this->app->make(AssignRole::class)->handle($actor, $target, $role, null, now(), null, null, null, 'direct-denial');
            self::fail('Unauthorized assignment was accepted.');
        } catch (AuthorizationException) {
            self::assertSame(1, SecurityEvent::query()->where('event_code', 'identity.authorization.denied')->count());
        }

        $response = $this->post('/admin/users/'.$target->public_id.'/role-assignments', [
            'role' => $role->public_id, 'scope_type' => 'GLOBAL', 'code' => 'private-submitted-code',
        ])->assertForbidden();
        self::assertSame(2, SecurityEvent::query()->where('event_code', 'identity.authorization.denied')->count());
        $event = SecurityEvent::query()->latest('id')->firstOrFail();
        self::assertSame($response->headers->get('X-Correlation-ID'), $event->correlation_id);
        self::assertStringNotContainsString('private-submitted-code', $event->toJson());
        self::assertStringNotContainsString($this->app->make(Session::class)->getId(), $event->toJson());
    }

    public function test_denial_survives_rollback_even_when_the_actor_was_created_in_that_transaction(): void
    {
        $this->seed(IdentityAuthorizationSeeder::class);
        $target = User::factory()->active()->create();
        $role = Role::query()->where('code', 'administrator')->sole();
        DB::beginTransaction();
        $actor = User::factory()->active()->create();
        try {
            $this->app->make(AssignRole::class)->handle($actor, $target, $role, null, now(), null, null, null, 'rolled-back-actor');
            self::fail('Unauthorized assignment was accepted.');
        } catch (AuthorizationException) {
            DB::rollBack();
        }
        $event = SecurityEvent::query()->where('correlation_id', 'rolled-back-actor')->sole();
        self::assertNull($event->actor_id);
        self::assertSame($actor->public_id, $event->metadata['actor_public_id']);
    }

    private function authenticate(User $user): void
    {
        $session = $this->app->make(Session::class);
        $session->start();
        $this->actingAs($user)->withCookie((string) config('session.cookie'), $session->getId());
        AuthSession::query()->create([
            'session_id' => $session->getId(), 'user_id' => $user->id, 'started_at' => now(),
            'last_seen_at' => now(), 'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(), 'mfa_authenticated_at' => now(),
            'reauthenticated_at' => now(), 'user_session_version' => $user->session_version,
        ]);
    }
}
