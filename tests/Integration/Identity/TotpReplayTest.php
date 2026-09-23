<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Application\Identity\Mfa\VerifyPendingMfa;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Services\Identity\OtpHasher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use OTPHP\TOTP;
use RuntimeException;
use Tests\TestCase;
use Throwable;

final class TotpReplayTest extends TestCase
{
    use DatabaseMigrations;

    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() !== 'mysql' || ! function_exists('pcntl_fork')) {
            $this->markTestSkipped('MySQL and pcntl are required.');
        }
    }

    public function test_concurrent_totp_verification_advances_the_timestep_once(): void
    {
        $user = User::factory()->privileged()->mfaConfirmed()->create();
        $method = $user->mfaMethods()->sole();
        $code = TOTP::createFromSecret($method->secret)->now();
        [$pending, $sessionId] = $this->pendingFor($user);
        [$first, $second] = $this->runConcurrently($pending->id, $sessionId, $code, 'totp');

        $results = [$first, $second];
        sort($results);
        self::assertSame(['rejected', 'success'], $results);
        DB::purge();
        DB::reconnect();
        self::assertNotNull($pending->fresh()->completed_at);
        self::assertNotNull($method->fresh()->last_accepted_timestep);
    }

    /** @return array{PendingAuthentication, string} */
    private function pendingFor(User $user): array
    {
        $sessionId = bin2hex(random_bytes(20));
        $session = $this->app->make(Session::class);
        $session->setId($sessionId);
        $session->start();
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

        return [$pending, $sessionId];
    }

    /** @return array{string, string} */
    private function runConcurrently(int $pendingId, string $sessionId, string $code, string $prefix): array
    {
        $barrier = tempnam(sys_get_temp_dir(), $prefix.'-barrier-');
        $first = tempnam(sys_get_temp_dir(), $prefix.'-first-');
        $second = tempnam(sys_get_temp_dir(), $prefix.'-second-');

        if ($barrier === false || $first === false || $second === false) {
            throw new RuntimeException('Unable to create concurrency files.');
        }

        unlink($barrier);

        try {
            $firstPid = $this->fork($barrier, $first, $pendingId, $sessionId, $code);
            $secondPid = $this->fork($barrier, $second, $pendingId, $sessionId, $code);
            touch($barrier);
            pcntl_waitpid($firstPid, $firstStatus);
            pcntl_waitpid($secondPid, $secondStatus);
            self::assertTrue(pcntl_wifexited($firstStatus));
            self::assertTrue(pcntl_wifexited($secondStatus));

            return [trim((string) file_get_contents($first)), trim((string) file_get_contents($second))];
        } finally {
            foreach ([$barrier, $first, $second] as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }
        }
    }

    private function fork(string $barrier, string $result, int $pendingId, string $sessionId, string $code): int
    {
        $pid = pcntl_fork();

        if ($pid === -1) {
            throw new RuntimeException('Unable to fork verification worker.');
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
            file_put_contents($result, 'success');
        } catch (ValidationException) {
            file_put_contents($result, 'rejected');
        } catch (Throwable $exception) {
            file_put_contents($result, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }
}
