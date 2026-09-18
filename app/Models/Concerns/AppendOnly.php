<?php

declare(strict_types=1);

namespace App\Models\Concerns;

use LogicException;

trait AppendOnly
{
    protected static function bootAppendOnly(): void
    {
        static::updating(static function (): void {
            throw new LogicException('Append-only records cannot be updated.');
        });

        static::deleting(static function (): void {
            throw new LogicException('Append-only records cannot be deleted.');
        });
    }
}
