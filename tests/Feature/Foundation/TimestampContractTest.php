<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Tests\TestCase;

final class TimestampContractTest extends TestCase
{
    public function test_scaffold_migrations_declare_microsecond_datetime_columns(): void
    {
        $usersMigration = file_get_contents(base_path('database/migrations/0001_01_01_000000_create_users_table.php'));
        $jobsMigration = file_get_contents(base_path('database/migrations/0001_01_01_000002_create_jobs_table.php'));

        self::assertStringContainsString("\$table->dateTime('email_verified_at', 6)->nullable();", $usersMigration);
        self::assertStringContainsString("\$table->dateTime('created_at', 6);", $usersMigration);
        self::assertStringContainsString("\$table->dateTime('updated_at', 6);", $usersMigration);
        self::assertStringContainsString("\$table->dateTime('created_at', 6)->nullable();", $usersMigration);
        self::assertStringContainsString("\$table->dateTime('failed_at', 6)->useCurrent();", $jobsMigration);
        self::assertStringNotContainsString('$table->timestamp(', $usersMigration);
        self::assertStringNotContainsString('$table->timestamps()', $usersMigration);
    }
}
