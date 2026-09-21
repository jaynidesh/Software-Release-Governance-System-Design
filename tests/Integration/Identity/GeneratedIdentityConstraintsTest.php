<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\Application;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

final class GeneratedIdentityConstraintsTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        if ($this->app->make('db')->connection()->getDriverName() !== 'mysql') {
            $this->markTestSkipped('MySQL 8.4 is required for generated identity constraint tests.');
        }
    }

    public function test_only_one_open_challenge_exists_per_user_and_purpose(): void
    {
        $user = User::factory()->active()->create();
        $challenge = $this->createChallenge($user);

        self::assertSame(1, $challenge->fresh()->open_slot);

        $this->expectException(QueryException::class);
        $this->createChallenge($user);
    }

    public function test_invalidated_challenge_releases_the_generated_open_slot(): void
    {
        $user = User::factory()->active()->create();
        $challenge = $this->createChallenge($user);
        $challenge->update(['invalidated_at' => now()]);

        self::assertNull($challenge->fresh()->open_slot);
        self::assertNotNull($this->createChallenge($user)->id);
    }

    public function test_only_one_active_pending_authentication_exists_per_user_and_purpose(): void
    {
        $user = User::factory()->active()->create();
        $firstChallenge = $this->createChallenge($user);
        $this->createPendingAuthentication($user, $firstChallenge);
        $firstChallenge->update(['invalidated_at' => now()]);
        $secondChallenge = $this->createChallenge($user);

        $this->expectException(QueryException::class);
        $this->createPendingAuthentication($user, $secondChallenge);
    }

    public function test_completed_pending_authentication_releases_the_generated_active_slot(): void
    {
        $user = User::factory()->active()->create();
        $firstChallenge = $this->createChallenge($user);
        $pending = $this->createPendingAuthentication($user, $firstChallenge);
        $pending->update(['completed_at' => now()]);
        $firstChallenge->update(['invalidated_at' => now()]);
        $secondChallenge = $this->createChallenge($user);

        self::assertNull($pending->fresh()->active_slot);
        self::assertNotNull($this->createPendingAuthentication($user, $secondChallenge)->id);
    }

    public function test_scope_key_prevents_duplicate_global_role_assignments(): void
    {
        $user = User::factory()->active()->create();
        $role = Role::factory()->create();
        $assignment = RoleAssignment::factory()->for($user)->for($role)->create();

        self::assertSame(0, $assignment->fresh()->scope_key);

        $this->expectException(QueryException::class);
        RoleAssignment::factory()->for($user)->for($role)->create();
    }

    public function test_scope_key_allows_the_same_role_in_distinct_application_scopes(): void
    {
        $user = User::factory()->active()->create();
        $role = Role::factory()->create();
        $first = Application::factory()->create();
        $second = Application::factory()->create();

        RoleAssignment::factory()->for($user)->for($role)->for($first)->create();
        RoleAssignment::factory()->for($user)->for($role)->for($second)->create();

        self::assertSame(2, $user->roleAssignments()->count());
    }

    public function test_normalized_email_uniqueness_is_race_safe(): void
    {
        User::factory()->create(['email' => ' Person@Example.COM ']);

        $this->expectException(QueryException::class);
        User::factory()->create(['email' => 'person@example.com']);
    }

    public function test_normalized_application_code_uniqueness_is_race_safe(): void
    {
        Application::factory()->create(['code' => ' RELEASE-PORTAL ']);

        $this->expectException(QueryException::class);
        Application::factory()->create(['code' => 'release-portal']);
    }

    public function test_normalized_role_code_uniqueness_is_race_safe(): void
    {
        Role::factory()->create(['code' => ' RELEASE-MANAGER ']);

        $this->expectException(QueryException::class);
        Role::factory()->create(['code' => 'release-manager']);
    }

    private function createChallenge(User $user): AuthChallenge
    {
        return AuthChallenge::create([
            'user_id' => $user->id,
            'purpose' => AuthenticationPurpose::Login,
            'code_hmac' => hash('sha256', fake()->uuid()),
            'expires_at' => now()->addMinutes(10),
        ]);
    }

    private function createPendingAuthentication(User $user, AuthChallenge $challenge): PendingAuthentication
    {
        return PendingAuthentication::create([
            'user_id' => $user->id,
            'auth_challenge_id' => $challenge->id,
            'purpose' => AuthenticationPurpose::Login,
            'session_id_hmac' => hash('sha256', fake()->uuid()),
            'user_session_version' => $user->session_version,
            'expires_at' => now()->addMinutes(10),
        ]);
    }
}
