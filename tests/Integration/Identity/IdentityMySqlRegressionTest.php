<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class IdentityMySqlRegressionTest extends TestCase
{
    use RefreshDatabase;

    public function test_mysql_generated_slots_reject_concurrent_open_challenge_and_global_assignment_duplicates(): void
    {
        self::assertSame('mysql', config('database.default'));
        self::assertSame('mysql', $this->app['db']->connection()->getDriverName());
        $user = User::factory()->active()->create();
        $role = Role::factory()->create();
        AuthChallenge::query()->create([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'code_hmac' => str_repeat('a', 64),
            'expires_at' => now()->addMinute(),
        ]);

        try {
            AuthChallenge::query()->create([
                'user_id' => $user->id,
                'purpose' => AuthenticationPurpose::Login,
                'code_hmac' => str_repeat('b', 64),
                'expires_at' => now()->addMinute(),
            ]);
            self::fail('A duplicate open challenge was accepted.');
        } catch (QueryException) {
            self::assertSame(1, AuthChallenge::query()->count());
        }

        RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => null,
        ]);

        try {
            RoleAssignment::factory()->create([
                'user_id' => $user->id,
                'role_id' => $role->id,
                'application_id' => null,
            ]);
            self::fail('A duplicate global role assignment was accepted.');
        } catch (QueryException) {
            self::assertSame(1, RoleAssignment::query()->count());
        }
    }
}
