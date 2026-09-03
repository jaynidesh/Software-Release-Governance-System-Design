<?php

declare(strict_types=1);

namespace App\Logging;

use Monolog\LogRecord;

final class RedactSensitiveContext
{
    private const SENSITIVE_PARTS = ['authorization', 'cookie', 'password', 'secret', 'token', 'api_key', 'private_key'];

    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(context: $this->redact($record->context), extra: $this->redact($record->extra));
    }

    /** @param array<array-key, mixed> $values @return array<array-key, mixed> */
    private function redact(array $values): array
    {
        foreach ($values as $key => $value) {
            $normalized = strtolower((string) $key);
            $sensitive = array_any(self::SENSITIVE_PARTS, static fn (string $part): bool => str_contains($normalized, $part));
            $values[$key] = $sensitive ? '[REDACTED]' : (is_array($value) ? $this->redact($value) : $value);
        }

        return $values;
    }
}
