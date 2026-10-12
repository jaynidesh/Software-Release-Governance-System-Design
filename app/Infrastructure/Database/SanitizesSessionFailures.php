<?php

declare(strict_types=1);

namespace App\Infrastructure\Database;

use App\Support\Exceptions\AuthenticatedSessionPersistenceException;
use Closure;
use Illuminate\Support\Facades\Log;
use Throwable;

trait SanitizesSessionFailures
{
    /** @param array<mixed> $bindings */
    protected function run($query, $bindings, Closure $callback): mixed
    {
        try {
            return parent::run($query, $bindings, $callback);
        } catch (Throwable $exception) {
            $tables = ['auth_sessions', (string) config('session.table', 'sessions')];
            $sensitive = false;
            foreach ($tables as $table) {
                if (preg_match('/(?<![a-z0-9_])'.preg_quote($this->getTablePrefix().$table, '/').'(?![a-z0-9_])/i', $query) === 1) {
                    $sensitive = true;
                    break;
                }
            }
            if (! $sensitive) {
                throw $exception;
            }

            $retryable = $this->causedByConcurrencyError($exception);
            try {
                Log::error('Session storage failed.', [
                    'exception_type' => $exception::class,
                    'correlation_id' => request()->attributes->get('correlation_id'),
                ]);
            } catch (Throwable) {
                // Diagnostics must never restore the original secret-bearing exception.
            }

            throw new AuthenticatedSessionPersistenceException($retryable);
        }
    }

    protected function causedByConcurrencyError(Throwable $exception): bool
    {
        return $exception instanceof AuthenticatedSessionPersistenceException
            ? $exception->retryable
            : parent::causedByConcurrencyError($exception);
    }
}
