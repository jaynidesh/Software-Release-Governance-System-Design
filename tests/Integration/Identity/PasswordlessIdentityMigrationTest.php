<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

final class PasswordlessIdentityMigrationTest extends TestCase
{
    private string $originalConnection;

    protected function setUp(): void
    {
        parent::setUp();

        $this->originalConnection = DB::getDefaultConnection();
        config()->set('database.connections.identity_migration_test', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);
        DB::purge('identity_migration_test');
        DB::setDefaultConnection('identity_migration_test');
    }

    protected function tearDown(): void
    {
        Schema::dropAllTables();
        DB::purge('identity_migration_test');
        DB::setDefaultConnection($this->originalConnection);

        parent::tearDown();
    }

    public function test_existing_users_are_normalized_and_deactivated_during_the_passwordless_cutover(): void
    {
        $foundationMigration = require database_path('migrations/0001_01_01_000000_create_users_table.php');
        $foundationMigration->up();

        DB::table('users')->insert([
            'name' => 'Legacy User',
            'email' => ' Legacy.User@Example.TEST ',
            'password' => 'legacy-password-hash',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $identityMigration = require database_path('migrations/2026_09_14_000100_add_passwordless_identity_to_users.php');
        $identityMigration->up();

        $user = DB::table('users')->sole();

        self::assertSame('legacy.user@example.test', $user->email);
        self::assertSame('DEACTIVATED', $user->state);
        self::assertSame(1, $user->session_version);
        self::assertNotNull($user->public_id);
    }
}
