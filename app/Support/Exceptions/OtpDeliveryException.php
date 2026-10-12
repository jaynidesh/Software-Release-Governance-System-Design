<?php

declare(strict_types=1);

namespace App\Support\Exceptions;

use Illuminate\Contracts\Debug\ShouldntReport;
use RuntimeException;

final class OtpDeliveryException extends RuntimeException implements ShouldntReport
{
    public function __construct(public readonly string $exceptionType)
    {
        parent::__construct('The one-time code could not be delivered.');
    }
}
