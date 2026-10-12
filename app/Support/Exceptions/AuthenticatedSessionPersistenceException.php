<?php

declare(strict_types=1);

namespace App\Support\Exceptions;

use Illuminate\Contracts\Debug\ShouldntReport;
use Illuminate\Database\QueryException;
use RuntimeException;

final class AuthenticatedSessionPersistenceException extends QueryException implements ShouldntReport
{
    public function __construct(public readonly bool $retryable = false)
    {
        $this->connectionName = '';
        $this->sql = '';
        $this->bindings = [];

        // Retain Laravel's insert-race recovery without QueryException's secret-bearing previous exception.
        RuntimeException::__construct('The authenticated session could not be persisted.');
    }

    public function getRawSql(): string
    {
        return '';
    }
}
