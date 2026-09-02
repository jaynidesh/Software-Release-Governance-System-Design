<?php

declare(strict_types=1);

namespace App\Application\Foundation;

use RuntimeException;

final class InvalidEnvironmentConfiguration extends RuntimeException
{
    /** @param list<string> $errors */
    public function __construct(public readonly array $errors)
    {
        parent::__construct(implode(' ', $errors));
    }
}
