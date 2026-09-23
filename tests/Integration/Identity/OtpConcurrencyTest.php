<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Services\Identity\OtpHasher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use RuntimeException;
use Tests\TestCase;
use Throwable;

final class OtpConcurrencyTest extends TestCase
{
    use DatabaseMigrations;

    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() !== 'mysql') {
            $this->markTestSkipped('MySQL 8.4 is required for OTP concurrency tests.');
        }

        if (! function_exists('pcntl_fork')) {
            $this->markTestSkipped('The pcntl extension is required for OTP concurrency tests.');
        }
    }

    public function test_concurrent_verification_consumes_the_challenge_exactly_once(): void
    {
        $user = User::factory()->privileged()->create();
        $code = '123456';
        $reference = strtolower((string) Str::ulid());
        $challenge = new AuthChallenge([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'code_hmac' => $this->app->make(OtpHasher::class)->hash(
                $code,
                $reference,
                $user->id,
                AuthenticationPurpose::Login,
            ),
            'expires_at' => now()->addMinutes(10),
            'delivered_at' => now(),
        ]);
        $challenge->public_id = $reference;
        $challenge->save();
        $barrier = tempnam(sys_get_temp_dir(), 'otp-barrier-');
        $firstResult = tempnam(sys_get_temp_dir(), 'otp-result-');
        $secondResult = tempnam(sys_get_temp_dir(), 'otp-result-');

        if ($barrier === false || $firstResult === false || $secondResult === false) {
            throw new RuntimeException('Unable to create OTP concurrency coordination files.');
        }

        unlink($barrier);

        try {
            $firstPid = $this->forkVerification($barrier, $firstResult, $reference, $code);
            $secondPid = $this->forkVerification($barrier, $secondResult, $reference, $code);
            touch($barrier);
            pcntl_waitpid($firstPid, $firstStatus);
            pcntl_waitpid($secondPid, $secondStatus);

            self::assertTrue(pcntl_wifexited($firstStatus));
            self::assertTrue(pcntl_wifexited($secondStatus));
            $results = [trim((string) file_get_contents($firstResult)), trim((string) file_get_contents($secondResult))];
            sort($results);
            self::assertSame(['rejected', 'success'], $results);

            DB::purge();
            DB::reconnect();
            self::assertNotNull($challenge->fresh()->consumed_at);
            self::assertSame(1, PendingAuthentication::query()->count());
        } finally {
            foreach ([$barrier, $firstResult, $secondResult] as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }
        }
    }

    private function forkVerification(
        string $barrier,
        string $resultPath,
        string $reference,
        string $code,
    ): int {
        $pid = pcntl_fork();

        if ($pid === -1) {
            throw new RuntimeException('Unable to fork OTP verification worker.');
        }

        if ($pid !== 0) {
            return $pid;
        }

        try {
            $deadline = microtime(true) + 5;

            while (! file_exists($barrier) && microtime(true) < $deadline) {
                usleep(1_000);
            }

            DB::purge();
            DB::reconnect();
            $session = $this->app->make(Session::class);
            $session->setId(Str::random(40));
            $session->start();

            try {
                $this->app->make(PrimaryAuthenticationProvider::class)->verify(
                    $reference,
                    $code,
                    AuthenticationPurpose::Login,
                    '127.0.0.1',
                    'Concurrency Test',
                    (string) Str::uuid(),
                );
                file_put_contents($resultPath, 'success');
            } catch (ValidationException) {
                file_put_contents($resultPath, 'rejected');
            }
        } catch (Throwable $exception) {
            file_put_contents($resultPath, 'error:'.$exception::class.':'.$exception->getMessage());
        }

        exit(0);
    }
}
