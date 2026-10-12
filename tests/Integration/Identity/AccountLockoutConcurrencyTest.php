<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Models\User;
use App\Services\Identity\AccountLockout;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;
use Throwable;

final class AccountLockoutConcurrencyTest extends TestCase
{
    use DatabaseMigrations;

    public function test_overlapping_failures_wait_for_the_user_lock_and_preserve_the_rolling_threshold(): void
    {
        if (DB::getDriverName() !== 'mysql' || ! function_exists('pcntl_fork')) {
            $this->markTestSkipped('MySQL and pcntl are required.');
        }
        $this->travelTo('2026-10-05 10:00:00');
        $user = User::factory()->active()->create();
        $lockout = $this->app->make(AccountLockout::class);
        $lockout->recordFailure($user);
        $this->travel(14)->minutes();
        for ($i = 0; $i < 3; $i++) {
            $lockout->recordFailure($user);
        }
        $this->travel(2)->minutes();
        $files = [];
        for ($i = 0; $i < 4; $i++) {
            $file = tempnam(sys_get_temp_dir(), 'lockout-race-');
            self::assertIsString($file);
            $files[] = $file;
        }
        $configuration = config('database.connections.'.DB::getDefaultConnection());
        DB::beginTransaction();
        User::query()->whereKey($user->id)->lockForUpdate()->firstOrFail();
        $pids = [];
        try {
            for ($i = 0; $i < 2; $i++) {
                $pid = pcntl_fork();
                self::assertNotSame(-1, $pid);
                if ($pid === 0) {
                    try {
                        config()->set('database.connections.lockout_worker', $configuration);
                        DB::setDefaultConnection('lockout_worker');
                        $staleUser = User::query()->findOrFail($user->id);
                        file_put_contents($files[$i * 2], 'ready');
                        $locked = $this->app->make(AccountLockout::class)->recordFailure($staleUser);
                        file_put_contents($files[$i * 2 + 1], $locked ? 'locked' : 'counted');
                    } catch (Throwable $exception) {
                        file_put_contents($files[$i * 2 + 1], 'error:'.$exception::class);
                    }
                    exit(0);
                }
                $pids[] = $pid;
            }
            $deadline = microtime(true) + 5;
            while ((file_get_contents($files[0]) !== 'ready' || file_get_contents($files[2]) !== 'ready') && microtime(true) < $deadline) {
                usleep(1000);
            }
            self::assertSame('ready', file_get_contents($files[0]));
            self::assertSame('ready', file_get_contents($files[2]));
            usleep(100000);
            self::assertSame('', file_get_contents($files[1]));
            self::assertSame('', file_get_contents($files[3]));
            DB::commit();
            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
                self::assertTrue(pcntl_wifexited($status));
            }
            $results = [file_get_contents($files[1]), file_get_contents($files[3])];
            sort($results);
            self::assertSame(['counted', 'locked'], $results);
            self::assertSame(5, $user->refresh()->failed_auth_attempts);
            self::assertCount(5, $user->auth_failure_timestamps);
            self::assertNotNull($user->locked_until);
        } finally {
            if (DB::transactionLevel() > 0) {
                DB::rollBack();
            }
            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
            }
            foreach ($files as $file) {
                unlink($file);
            }
        }
    }
}
