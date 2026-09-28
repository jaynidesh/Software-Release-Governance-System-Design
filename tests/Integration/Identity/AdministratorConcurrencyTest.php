<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

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
