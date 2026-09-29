<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Application\Identity\Assignments\AssignRole;
use App\Application\Identity\Assignments\RevokeRoleAssignment;
use App\Application\Identity\Roles\ChangeRoleState;
use App\Application\Identity\Roles\SyncRolePermissions;
use App\Application\Identity\Users\ChangeUserState;
use App\Application\Identity\Users\ResendInvitation;
use App\Application\Identity\Users\RevokeInvitation;
use App\Application\Identity\Users\UnlockUser;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\AuthSession;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Services\Identity\EloquentAuthorizationService;
use App\Support\Exceptions\DomainRuleViolation;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use RuntimeException;
use Symfony\Component\Console\Tester\CommandTester;
use Tests\TestCase;
use Throwable;

final class AdministratorConcurrencyTest extends TestCase
{
    use DatabaseMigrations;

    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() !== 'mysql' || ! function_exists('pcntl_fork')) {
            $this->markTestSkipped('MySQL 8.4 and pcntl are required for administrator concurrency tests.');
        }

        $this->seed(IdentityAuthorizationSeeder::class);
        Notification::fake();
        $this->app->bind(AuthorizationService::class, fn () => new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $requiresFreshReauthentication
                    && in_array($permission, ['admin.users', 'admin.roles'], true);
            }
        });
    }

    public function test_two_interactive_bootstraps_cannot_both_create_an_administrator(): void
    {
        $results = $this->forkWorkers([
            fn (string $path): never => $this->runBootstrap($path, 'first@example.test'),
            fn (string $path): never => $this->runBootstrap($path, 'second@example.test'),
        ]);
        sort($results);

        self::assertSame(['failure', 'success'], $results);
        DB::purge();
        DB::reconnect();
        self::assertSame(1, RoleAssignment::query()
            ->where('role_id', Role::query()->where('code', 'administrator')->value('id'))
            ->whereNull('application_id')
            ->whereNull('revoked_at')
            ->count());
        self::assertSame(1, User::query()->count());
    }

    public function test_concurrent_user_state_changes_cannot_remove_both_effective_administrators(): void
    {
        [$first, $second] = $this->effectiveAdministrators();
        $results = $this->forkWorkers([
            fn (string $path): never => $this->runStateChange($path, $first->id, $second->id),
            fn (string $path): never => $this->runStateChange($path, $second->id, $first->id),
        ]);
        sort($results);

        self::assertSame(['protected', 'success'], $results);
        DB::purge();
        DB::reconnect();
        self::assertSame(1, User::query()->where('state', UserState::Active)->count());
    }

    public function test_time_travel_cannot_hide_assignment_expiry_when_protecting_the_last_administrator(): void
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        $finalAssignment = RoleAssignment::factory()->create([
            'user_id' => $target->id,
            'role_id' => $administrator->id,
        ]);
        RoleAssignment::factory()->create([
            'user_id' => User::factory()->active()->create()->id,
            'role_id' => $administrator->id,
            'starts_at' => now()->subHour(),
            'ends_at' => now()->addMinute(),
        ]);
        $this->travel(2)->minutes();

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(RevokeRoleAssignment::class)->handle($actor, $finalAssignment, null, null, null);
    }

    public function test_time_travel_protects_the_last_administrator_from_role_deactivation(): void
    {
        [$actor, $target, $role] = $this->customRoleLastAdministrator();
        $this->travel(2)->minutes();

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(ChangeRoleState::class)->handle($actor, $role, false, null, null, null);
    }

    public function test_time_travel_protects_the_last_administrator_from_permission_removal(): void
    {
        [$actor, $target, $role] = $this->customRoleLastAdministrator();
        $this->travel(2)->minutes();

        $this->expectException(DomainRuleViolation::class);
        $this->app->make(SyncRolePermissions::class)->handle($actor, $role, [], null, null, null);
    }

    public function test_assignment_update_contends_on_the_mutex_and_rolls_back_the_split_permission_union(): void
    {
        $actor = $this->realAuthorizationActor('admin.roles');
        [$target, $usersRole, $rolesRole, $rolesAssignment] = $this->splitRoleAdministrator();
        $results = $this->runWhileAdministratorMutexHeld([
            fn (string $path): never => $this->runAssignmentReschedule(
                $path,
                $actor->id,
                $target->id,
                $rolesRole->id,
            ),
        ]);

        self::assertSame(['protected'], $results);
        DB::purge();
        DB::reconnect();
        self::assertLessThanOrEqual(now(), $rolesAssignment->fresh()->starts_at);
        $this->assertSplitPermissionUnion($target->id, $usersRole->id, $rolesRole->id);
    }

    public function test_role_state_change_contends_on_the_mutex_and_rolls_back_the_split_permission_union(): void
    {
        $actor = $this->realAuthorizationActor('admin.roles');
        [$target, $usersRole, $rolesRole] = $this->splitRoleAdministrator();
        $results = $this->runWhileAdministratorMutexHeld([
            fn (string $path): never => $this->runRoleStateChange($path, $actor->id, $usersRole->id),
        ]);

        self::assertSame(['protected'], $results);
        DB::purge();
        DB::reconnect();
        self::assertTrue($usersRole->fresh()->is_active);
        $this->assertSplitPermissionUnion($target->id, $usersRole->id, $rolesRole->id);
    }

    public function test_permission_change_contends_on_the_mutex_and_rolls_back_the_split_permission_union(): void
    {
        $actor = $this->realAuthorizationActor('admin.roles');
        [$target, $usersRole, $rolesRole] = $this->splitRoleAdministrator();
        $results = $this->runWhileAdministratorMutexHeld([
            fn (string $path): never => $this->runPermissionRemoval($path, $actor->id, $usersRole->id),
        ]);

        self::assertSame(['protected'], $results);
        DB::purge();
        DB::reconnect();
        $this->assertSplitPermissionUnion($target->id, $usersRole->id, $rolesRole->id);
    }

    public function test_mixed_role_and_assignment_mutations_overlap_and_both_roll_back(): void
    {
        $actor = $this->realAuthorizationActor('admin.roles');
        [$target, $usersRole, $rolesRole, $rolesAssignment] = $this->splitRoleAdministrator();
        $results = $this->runWhileAdministratorMutexHeld([
            fn (string $path): never => $this->runRoleStateChange($path, $actor->id, $usersRole->id),
            fn (string $path): never => $this->runAssignmentReschedule(
                $path,
                $actor->id,
                $target->id,
                $rolesRole->id,
            ),
        ]);
        sort($results);

        self::assertSame(['protected', 'protected'], $results);
        DB::purge();
        DB::reconnect();
        self::assertTrue($usersRole->fresh()->is_active);
        self::assertLessThanOrEqual(now(), $rolesAssignment->fresh()->starts_at);
        $this->assertSplitPermissionUnion($target->id, $usersRole->id, $rolesRole->id);
    }

    public function test_bootstrap_history_is_serialized_even_after_the_original_grant_is_revoked(): void
    {
        $this->runBootstrapInline('initial-history@example.test');
        RoleAssignment::query()->update(['revoked_at' => now()]);

        $results = $this->runWhileAdministratorMutexHeld([
            fn (string $path): never => $this->runBootstrap($path, 'replacement-one@example.test'),
            fn (string $path): never => $this->runBootstrap($path, 'replacement-two@example.test'),
        ]);
        sort($results);

        self::assertSame(['failure', 'failure'], $results);
        DB::purge();
        DB::reconnect();
        self::assertSame(1, User::query()->count());
    }

    public function test_actor_suspension_races_cannot_authorize_invitation_or_unlock_mutations(): void
    {
        foreach (['resend', 'revoke', 'unlock'] as $operation) {
            $actor = $this->realAuthorizationActor('admin.users');
            $target = $operation === 'unlock'
                ? User::factory()->locked()->create()
                : User::factory()->invited()->create();
            $originalExpiry = $target->invitation_expires_at;
            $originalVersion = $target->session_version;
            $result = $this->runActorSuspensionRace(
                $actor,
                fn (string $path): never => $this->runUserSecurityAction(
                    $path,
                    $operation,
                    $actor->id,
                    $target->id,
                ),
            );

            self::assertSame('denied', $result);
            DB::purge();
            DB::reconnect();
            self::assertSame($originalVersion, $target->fresh()->session_version);

            if ($operation !== 'unlock') {
                self::assertTrue($target->fresh()->invitation_expires_at->equalTo($originalExpiry));
            }
        }
    }

    /** @return array{User, User} */
    private function effectiveAdministrators(): array
    {
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        $first = User::factory()->active()->create();
        $second = User::factory()->active()->create();
        RoleAssignment::factory()->create(['user_id' => $first->id, 'role_id' => $administrator->id]);
        RoleAssignment::factory()->create(['user_id' => $second->id, 'role_id' => $administrator->id]);

        return [$first, $second];
    }

    /** @return array{User, User, Role} */
    private function customRoleLastAdministrator(): array
    {
        $actor = User::factory()->active()->create();
        $target = User::factory()->active()->create();
        $role = Role::factory()->create();
        $role->permissions()->attach(Permission::query()
            ->whereIn('code', ['admin.users', 'admin.roles'])
            ->pluck('id'));
        RoleAssignment::factory()->create([
            'user_id' => $target->id,
            'role_id' => $role->id,
            'starts_at' => now()->subMinute(),
        ]);
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        RoleAssignment::factory()->create([
            'user_id' => User::factory()->active()->create()->id,
            'role_id' => $administrator->id,
            'starts_at' => now()->subHour(),
            'ends_at' => now()->addMinute(),
        ]);

        return [$actor, $target, $role];
    }

    /** @return array{User, Role, Role, RoleAssignment} */
    private function splitRoleAdministrator(): array
    {
        $target = User::factory()->active()->create();
        $usersRole = Role::factory()->create();
        $rolesRole = Role::factory()->create();
        $usersRole->permissions()->attach(Permission::query()->where('code', 'admin.users')->value('id'));
        $rolesRole->permissions()->attach(Permission::query()->where('code', 'admin.roles')->value('id'));
        RoleAssignment::factory()->create(['user_id' => $target->id, 'role_id' => $usersRole->id]);
        $rolesAssignment = RoleAssignment::factory()->create([
            'user_id' => $target->id,
            'role_id' => $rolesRole->id,
        ]);

        return [$target, $usersRole, $rolesRole, $rolesAssignment];
    }

    private function realAuthorizationActor(string $permissionCode): User
    {
        $actor = User::factory()->active()->mfaConfirmed()->create();
        $role = Role::factory()->create();
        $role->permissions()->attach(Permission::query()->where('code', $permissionCode)->value('id'));
        RoleAssignment::factory()->create(['user_id' => $actor->id, 'role_id' => $role->id]);
        $session = $this->app->make(Session::class);
        $sessionId = str_pad((string) $actor->id, 40, '4', STR_PAD_LEFT);
        $session->setId($sessionId);
        AuthSession::query()->create([
            'session_id' => $sessionId,
            'user_id' => $actor->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'mfa_authenticated_at' => now(),
            'reauthenticated_at' => now(),
            'user_session_version' => $actor->session_version,
        ]);

        return $actor;
    }

    /**
     * @param  non-empty-list<callable(string): never>  $workers
     * @return list<string>
     */
    private function runWhileAdministratorMutexHeld(array $workers): array
    {
        DB::beginTransaction();
        Role::query()->where('code', 'administrator')->lockForUpdate()->firstOrFail();

        return $this->runContendedWorkers($workers, static function (): void {
            DB::commit();
        });
    }

    /** @param callable(string): never $worker */
    private function runActorSuspensionRace(User $actor, callable $worker): string
    {
        DB::beginTransaction();
        $lockedActor = User::query()->whereKey($actor->id)->lockForUpdate()->firstOrFail();
        $results = $this->runContendedWorkers([$worker], static function () use ($lockedActor): void {
            $lockedActor->forceFill(['state' => UserState::Suspended])->save();
            DB::commit();
        });

        return $results[0];
    }

    /**
     * @param  non-empty-list<callable(string): never>  $workers
     * @return list<string>
     */
    private function runContendedWorkers(array $workers, callable $release): array
    {
        $startedPaths = [];
        $resultPaths = [];
        $pids = [];

        try {
            foreach ($workers as $worker) {
                $started = tempnam(sys_get_temp_dir(), 'administrator-started-');
                $result = tempnam(sys_get_temp_dir(), 'administrator-result-');

                if ($started === false || $result === false) {
                    throw new RuntimeException('Unable to create administrator contention files.');
                }

                unlink($started);
                $startedPaths[] = $started;
                $resultPaths[] = $result;
                $pid = pcntl_fork();

                if ($pid === -1) {
                    throw new RuntimeException('Unable to fork administrator contention worker.');
                }

                if ($pid === 0) {
                    $this->connectForkWorker();
                    touch($started);
                    $worker($result);
                }

                $pids[] = $pid;
            }

            $deadline = microtime(true) + 5;

            do {
                $allStarted = collect($startedPaths)->every(static fn (string $path): bool => file_exists($path));

                if (! $allStarted) {
                    usleep(1_000);
                }
            } while (! $allStarted && microtime(true) < $deadline);

            self::assertTrue($allStarted, 'Contention workers did not start.');
            usleep(200_000);

            foreach ($resultPaths as $path) {
                self::assertSame('', (string) file_get_contents($path), 'Mutation completed without waiting for the lock.');
            }

            $release();

            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
                self::assertTrue(pcntl_wifexited($status));
            }

            return array_map(
                static fn (string $path): string => trim((string) file_get_contents($path)),
                $resultPaths,
            );
        } finally {
            if (DB::transactionLevel() > 0) {
                DB::rollBack();
            }

            foreach ([...$startedPaths, ...$resultPaths] as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }
        }
    }

    private function connectForkWorker(): void
    {
        $connectionName = 'mysql_worker_'.getmypid();
        config(["database.connections.{$connectionName}" => config('database.connections.mysql')]);
        DB::setDefaultConnection($connectionName);
        DB::connection()->getPdo();
    }

    /**
     * @param  array{callable(string): never, callable(string): never}  $workers
     * @return array{string, string}
     */
    private function forkWorkers(array $workers): array
    {
        $barrier = tempnam(sys_get_temp_dir(), 'administrator-barrier-');
        $paths = [
            tempnam(sys_get_temp_dir(), 'administrator-result-'),
            tempnam(sys_get_temp_dir(), 'administrator-result-'),
        ];

        if ($barrier === false || in_array(false, $paths, true)) {
            throw new RuntimeException('Unable to create administrator concurrency coordination files.');
        }

        /** @var array{string, string} $paths */
        unlink($barrier);

        try {
            $pids = [];

            foreach ($workers as $index => $worker) {
                $pid = pcntl_fork();

                if ($pid === -1) {
                    throw new RuntimeException('Unable to fork administrator concurrency worker.');
                }

                if ($pid === 0) {
                    $this->waitForBarrier($barrier);
                    $worker($paths[$index]);
                }

                $pids[] = $pid;
            }

            touch($barrier);

            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
                self::assertTrue(pcntl_wifexited($status));
            }

            return [trim((string) file_get_contents($paths[0])), trim((string) file_get_contents($paths[1]))];
        } finally {
            foreach ([$barrier, ...$paths] as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }
        }
    }

    private function runBootstrap(string $path, string $email): never
    {
        try {
            DB::purge();
            DB::reconnect();
            $tester = new CommandTester(Artisan::all()['identity:bootstrap-admin']);
            $tester->setInputs(['', 'Concurrent Administrator', $email, 'UTC']);
            $status = $tester->execute([], ['interactive' => true]);
            file_put_contents($path, $status === 0 ? 'success' : 'failure');
        } catch (Throwable $exception) {
            file_put_contents($path, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }

    private function runBootstrapInline(string $email): void
    {
        $tester = new CommandTester(Artisan::all()['identity:bootstrap-admin']);
        $tester->setInputs(['', 'Initial Administrator', $email, 'UTC']);
        self::assertSame(0, $tester->execute([], ['interactive' => true]));
    }

    private function runAssignmentReschedule(
        string $path,
        int $actorId,
        int $targetId,
        int $roleId,
    ): never {
        try {
            $this->useRealAuthorization();
            $this->app->make(AssignRole::class)->handle(
                User::query()->findOrFail($actorId),
                User::query()->findOrFail($targetId),
                Role::query()->findOrFail($roleId),
                null,
                now()->addHour(),
                null,
                null,
                null,
                null,
            );
            file_put_contents($path, 'lost');
        } catch (DomainRuleViolation) {
            file_put_contents($path, 'protected');
        } catch (Throwable $exception) {
            file_put_contents($path, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }

    private function runRoleStateChange(string $path, int $actorId, int $roleId): never
    {
        try {
            $this->useRealAuthorization();
            $this->app->make(ChangeRoleState::class)->handle(
                User::query()->findOrFail($actorId),
                Role::query()->findOrFail($roleId),
                false,
                null,
                null,
                null,
            );
            file_put_contents($path, 'lost');
        } catch (DomainRuleViolation) {
            file_put_contents($path, 'protected');
        } catch (Throwable $exception) {
            file_put_contents($path, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }

    private function runPermissionRemoval(string $path, int $actorId, int $roleId): never
    {
        try {
            $this->useRealAuthorization();
            $this->app->make(SyncRolePermissions::class)->handle(
                User::query()->findOrFail($actorId),
                Role::query()->findOrFail($roleId),
                [],
                null,
                null,
                null,
            );
            file_put_contents($path, 'lost');
        } catch (DomainRuleViolation) {
            file_put_contents($path, 'protected');
        } catch (Throwable $exception) {
            file_put_contents($path, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }

    private function runUserSecurityAction(
        string $path,
        string $operation,
        int $actorId,
        int $targetId,
    ): never {
        try {
            $this->useRealAuthorization();
            $actor = User::query()->findOrFail($actorId);
            $target = User::query()->findOrFail($targetId);

            match ($operation) {
                'resend' => $this->app->make(ResendInvitation::class)
                    ->handle($actor, $target, null, null, null),
                'revoke' => $this->app->make(RevokeInvitation::class)
                    ->handle($actor, $target, null, null, null),
                'unlock' => $this->app->make(UnlockUser::class)
                    ->handle($actor, $target, null, null, null),
            };
            file_put_contents($path, 'mutated');
        } catch (AuthorizationException) {
            file_put_contents($path, 'denied');
        } catch (Throwable $exception) {
            file_put_contents($path, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }

    private function useRealAuthorization(): void
    {
        $this->app->bind(AuthorizationService::class, EloquentAuthorizationService::class);
    }

    private function assertSplitPermissionUnion(int $userId, int $usersRoleId, int $rolesRoleId): void
    {
        self::assertSame(['admin.users'], Role::query()->findOrFail($usersRoleId)->permissions()->pluck('code')->all());
        self::assertSame(['admin.roles'], Role::query()->findOrFail($rolesRoleId)->permissions()->pluck('code')->all());
        self::assertSame(2, RoleAssignment::query()
            ->where('user_id', $userId)
            ->whereNull('application_id')
            ->whereNull('revoked_at')
            ->where('starts_at', '<=', now())
            ->where(static function ($query): void {
                $query->whereNull('ends_at')->orWhere('ends_at', '>', now());
            })
            ->count());
    }

    private function runStateChange(string $path, int $actorId, int $targetId): never
    {
        try {
            DB::purge();
            DB::reconnect();
            $this->app->make(ChangeUserState::class)->handle(
                User::query()->findOrFail($actorId),
                User::query()->findOrFail($targetId),
                UserState::Deactivated,
                null,
                null,
                null,
            );
            file_put_contents($path, 'success');
        } catch (DomainRuleViolation) {
            file_put_contents($path, 'protected');
        } catch (Throwable $exception) {
            file_put_contents($path, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }

    private function waitForBarrier(string $barrier): void
    {
        $deadline = microtime(true) + 5;

        while (! file_exists($barrier) && microtime(true) < $deadline) {
            usleep(1_000);
        }
    }
}
