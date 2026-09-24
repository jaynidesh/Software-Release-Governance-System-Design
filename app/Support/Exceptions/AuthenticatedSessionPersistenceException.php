<?php

declare(strict_types=1);

namespace App\Support\Exceptions;

use Illuminate\Contracts\Debug\ShouldntReport;
use RuntimeException;

final class AuthenticatedSessionPersistenceException extends RuntimeException implements ShouldntReport
{
    public function __construct()
    {
        parent::__construct('The authenticated session could not be persisted.');
    }
}
