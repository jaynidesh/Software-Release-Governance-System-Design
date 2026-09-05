<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Illuminate\Log\Logger;
use Illuminate\Support\Facades\Log;
use Monolog\Handler\ProcessableHandlerInterface;
use Monolog\Logger as MonologLogger;
use Monolog\LogRecord;
use Tests\TestCase;

final class StructuredLoggingTest extends TestCase
{
    public function test_configured_json_logger_redacts_before_interpolation_and_at_the_handler(): void
    {
        $stream = fopen('php://temp', 'w+');
        self::assertIsResource($stream);

        config(['logging.channels.stderr.handler_with.stream' => $stream]);
        Log::forgetChannel('stderr');
        Log::shareContext(['correlation_id' => '00000000-0000-4000-8000-000000000123']);

        try {
            $logger = Log::channel('stderr');
            self::assertInstanceOf(Logger::class, $logger);

            $monolog = $logger->getLogger();
            self::assertInstanceOf(MonologLogger::class, $monolog);

            $handler = $monolog->getHandlers()[0];
            self::assertInstanceOf(ProcessableHandlerInterface::class, $handler);
            $handler->pushProcessor(static fn (LogRecord $record): LogRecord => $record->with(extra: [
                'transport' => [
                    'api_token' => 'EXTRA-TOKEN-SECRET',
                    'attempt' => 2,
                ],
            ]));

            $logger->info('Authenticated {email} with {password}', [
                'email' => 'user@example.test',
                'password' => 'INTERPOLATED-PASSWORD-SECRET',
            ]);

            rewind($stream);
            $output = stream_get_contents($stream);
            self::assertIsString($output);
            self::assertStringNotContainsString('INTERPOLATED-PASSWORD-SECRET', $output);
            self::assertStringNotContainsString('EXTRA-TOKEN-SECRET', $output);

            $record = json_decode($output, true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('Authenticated user@example.test with [REDACTED]', $record['message']);
            self::assertSame('user@example.test', $record['context']['email']);
            self::assertSame('[REDACTED]', $record['context']['password']);
            self::assertSame('00000000-0000-4000-8000-000000000123', $record['context']['correlation_id']);
            self::assertSame('[REDACTED]', $record['extra']['transport']['api_token']);
            self::assertSame(2, $record['extra']['transport']['attempt']);
        } finally {
            Log::forgetChannel('stderr');
            Log::flushSharedContext();
            fclose($stream);
        }
    }
}
