<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Application\Identity\Mfa\VerifyPendingMfa;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Models\UserRecoveryCode;
use App\Services\Identity\OtpHasher;
use App\Services\Identity\RecoveryCodeHasher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use RuntimeException;
use Tests\TestCase;
use Throwable;

final class RecoveryCodeConcurrencyTest extends TestCase
{
    use DatabaseMigrations;

    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() !== 'mysql' || ! function_exists('pcntl_fork')) {
            $this->markTestSkipped('MySQL and pcntl are required.');
        }
    }

    public function test_concurrent_recovery_verification_consumes_the_code_once(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $method = $user->mfaMethods()->sole();
        $plain = 'ABCD-EFGH-IJKL';
        $recovery = UserRecoveryCode::query()->create([
            'user_mfa_method_id' => $method->id,
            'code_hmac' => $this->app->make(RecoveryCodeHasher::class)->hash($plain, $method->id),
        ]);
        $sessionId = bin2hex(random_bytes(20));
        $this->app->make(Session::class)->setId($sessionId);
        $challenge = AuthChallenge::query()->create([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'code_hmac' => str_repeat('a', 64),
            'expires_at' => now()->addMinutes(10),
            'delivered_at' => now(),
            'consumed_at' => now(),
        ]);
        $pending = PendingAuthentication::query()->create([
            'user_id' => $user->id,
            'auth_challenge_id' => $challenge->id,
            'purpose' => AuthenticationPurpose::Login,
            'session_id_hmac' => $this->app->make(OtpHasher::class)->hashSessionId($sessionId),
            'user_session_version' => $user->session_version,
            'expires_at' => now()->addMinutes(10),
        ]);
        $results = $this->workers($pending->id, $sessionId, $plain);
        sort($results);

        self::assertSame(['rejected', 'success'], $results);
        DB::purge();
        DB::reconnect();
        self::assertNotNull($recovery->fresh()->used_at);
        self::assertNotNull($pending->fresh()->completed_at);
    }

    /** @return array{string, string} */
    private function workers(int $pendingId, string $sessionId, string $code): array
    {
        $barrier = tempnam(sys_get_temp_dir(), 'recovery-barrier-');
        $paths = [tempnam(sys_get_temp_dir(), 'recovery-result-'), tempnam(sys_get_temp_dir(), 'recovery-result-')];

        if ($barrier === false || in_array(false, $paths, true)) {
            throw new RuntimeException('Unable to create concurrency files.');
        }

        /** @var array{string, string} $paths */
        unlink($barrier);

        try {
            $pids = array_map(fn (string $path): int => $this->fork($barrier, $path, $pendingId, $sessionId, $code), $paths);
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

    private function fork(string $barrier, string $path, int $pendingId, string $sessionId, string $code): int
    {
        $pid = pcntl_fork();

        if ($pid === -1) {
            throw new RuntimeException('Unable to fork recovery worker.');
        }

        if ($pid !== 0) {
            return $pid;
        }

        try {
            while (! file_exists($barrier)) {
                usleep(1_000);
            }

            DB::purge();
            DB::reconnect();
            $session = $this->app->make(Session::class);
            $session->start();
            $session->setId($sessionId);
            $this->app->instance(Session::class, $session);
            $pending = PendingAuthentication::query()->findOrFail($pendingId);
            $this->app->make(VerifyPendingMfa::class)->handle(
                $pending,
                $code,
                '127.0.0.1',
                'Concurrency Test',
                null,
            );
            file_put_contents($path, 'success');
        } catch (ValidationException) {
            file_put_contents($path, 'rejected');
        } catch (Throwable $exception) {
            file_put_contents($path, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }
}
