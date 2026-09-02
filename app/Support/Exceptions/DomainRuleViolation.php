<?php

declare(strict_types=1);

namespace App\Support\Exceptions;

use RuntimeException;

final class DomainRuleViolation extends RuntimeException
{
    /** @param list<string> $failures */
    public function __construct(public readonly string $ruleCode, public readonly array $failures)
    {
        parent::__construct('The requested action is not permitted.');
    }
}
