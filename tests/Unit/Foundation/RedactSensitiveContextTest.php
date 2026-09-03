<?php

declare(strict_types=1);

namespace Tests\Unit\Foundation;

use App\Logging\RedactSensitiveContext;
use DateTimeImmutable;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;

final class RedactSensitiveContextTest extends TestCase
{
    public function test_sensitive_keys_are_redacted_at_every_depth(): void
    {
        $record = new LogRecord(new DateTimeImmutable, 'test', Level::Info, 'request', [
            'email' => 'user@example.test', 'password' => 'secret',
            'headers' => ['Authorization' => 'Bearer secret', 'accept' => 'application/json'], 'smtp_token' => 'secret',
        ]);
        $redacted = (new RedactSensitiveContext)($record);

        self::assertSame('user@example.test', $redacted->context['email']);
        self::assertSame('[REDACTED]', $redacted->context['password']);
        self::assertSame('[REDACTED]', $redacted->context['headers']['Authorization']);
        self::assertSame('application/json', $redacted->context['headers']['accept']);
        self::assertSame('[REDACTED]', $redacted->context['smtp_token']);
    }
}
