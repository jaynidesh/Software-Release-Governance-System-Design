<?php

declare(strict_types=1);

namespace App\Services\Foundation;

use App\Contracts\Foundation\ReadinessCheck;
use Illuminate\Database\DatabaseManager;
use Throwable;

final readonly class DatabaseReadinessCheck implements ReadinessCheck
{
    public function __construct(private DatabaseManager $database) {}

    public function check(): bool
    {
        try {
            return (int) $this->database->selectOne('SELECT 1 AS ready')->ready === 1;
        } catch (Throwable) {
            return false;
        }
    }
}
