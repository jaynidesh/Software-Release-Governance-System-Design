<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Models\AuthChallenge;
use App\Models\SecurityEvent;
use App\Models\User;
use Illuminate\Contracts\Debug\ShouldntReport;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Notifications\Events\NotificationFailed;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\AbstractTransport;
use Tests\TestCase;

final class OtpTransportPrivacyTest extends TestCase
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

    public function test_real_queued_transport_failure_retries_and_fails_without_secret_bearing_exceptions(): void
    {
        $user = User::factory()->active()->create();
        $this->post('/login/otp', ['email' => $user->email]);
        $payload = json_decode(DB::table('jobs')->sole()->payload, true, flags: JSON_THROW_ON_ERROR);
        $job = unserialize($this->app->make(Encrypter::class)->decrypt($payload['data']['command']));
        $code = $job->notification->code;
        $transport = new class($code, $user->email) extends AbstractTransport
        {
            public function __construct(private string $code, private string $email)
            {
                parent::__construct();
            }

            protected function doSend(SentMessage $message): void
            {
                throw new TransportException('Rejected OTP '.$this->code.' for '.$this->email);
            }

            public function __toString(): string
            {
                return 'failing-test';
            }
        };
        Mail::extend('failing-test', static fn () => $transport);
        config()->set('mail.mailers.failing-test', ['transport' => 'failing-test']);
        config()->set('mail.default', 'failing-test');
        $handler = new TestHandler;
        Log::swap(new Logger('otp-privacy', [$handler]));
        $failures = [];
        Event::listen(NotificationFailed::class, function (NotificationFailed $event) use (&$failures): void {
            $failures[] = $event->data['exception'];
        });

        foreach ([1, 2] as $attempt) {
            Artisan::call('queue:work', ['--once' => true, '--queue' => 'security', '--tries' => 2, '--backoff' => 0]);
            self::assertNull(AuthChallenge::query()->sole()->delivered_at);
            self::assertSame(2 - $attempt, DB::table('jobs')->count());
        }

        self::assertCount(2, $failures);
        self::assertSame(1, DB::table('failed_jobs')->count());
        $evidence = json_encode([
            $handler->getRecords(), DB::table('failed_jobs')->sole(),
            SecurityEvent::query()->get()->toArray(),
        ], JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString($code, $evidence);
        self::assertStringNotContainsString($user->email, $evidence);
        foreach ($failures as $failure) {
            self::assertInstanceOf(ShouldntReport::class, $failure);
            self::assertNull($failure->getPrevious());
            self::assertStringNotContainsString($code, (string) $failure);
        }
        self::assertSame(2, SecurityEvent::query()->where('event_code', 'identity.otp.delivery_failed')->count());
    }
}
