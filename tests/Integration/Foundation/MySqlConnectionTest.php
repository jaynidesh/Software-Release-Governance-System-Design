<?php

declare(strict_types=1);

namespace Tests\Integration\Foundation;

use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class MySqlConnectionTest extends TestCase
{
    public function test_suite_uses_mysql_and_can_query_it(): void
    {
        self::assertSame('mysql', config('database.default'));
        self::assertSame(1, (int) DB::selectOne('SELECT 1 AS ready')->ready);
    }
}
