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
        $record = new LogRecord(
            new DateTimeImmutable,
            'test',
            Level::Info,
            'request',
            [
                'email' => 'user@example.test', 'password' => 'secret',
                'headers' => ['Authorization' => 'Bearer secret', 'accept' => 'application/json'], 'smtp_token' => 'secret',
                'otp' => '123456', 'verification_code' => '123456', 'normalized_email' => 'user@example.test',
                'totp' => '123456', 'recovery_code' => 'secret', 'mfa_secret' => 'secret',
            ],
            [
                'transport' => ['private_key' => 'secret', 'attempt' => 2],
                'region' => 'mu',
            ],
        );
        $redacted = (new RedactSensitiveContext)($record);

        self::assertSame('user@example.test', $redacted->context['email']);
        self::assertSame('[REDACTED]', $redacted->context['password']);
        self::assertSame('[REDACTED]', $redacted->context['headers']['Authorization']);
        self::assertSame('application/json', $redacted->context['headers']['accept']);
        self::assertSame('[REDACTED]', $redacted->context['smtp_token']);
        self::assertSame('[REDACTED]', $redacted->context['otp']);
        self::assertSame('[REDACTED]', $redacted->context['verification_code']);
        self::assertSame('[REDACTED]', $redacted->context['normalized_email']);
        self::assertSame('[REDACTED]', $redacted->context['totp']);
        self::assertSame('[REDACTED]', $redacted->context['recovery_code']);
        self::assertSame('[REDACTED]', $redacted->context['mfa_secret']);
        self::assertSame('[REDACTED]', $redacted->extra['transport']['private_key']);
        self::assertSame(2, $redacted->extra['transport']['attempt']);
        self::assertSame('mu', $redacted->extra['region']);
    }
}
