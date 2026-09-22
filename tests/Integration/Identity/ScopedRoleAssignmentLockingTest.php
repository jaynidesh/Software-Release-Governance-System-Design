<?php

declare(strict_types=1);

namespace Tests\Integration\Identity;

use App\Models\Application;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class ScopedRoleAssignmentLockingTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() !== 'mysql') {
            $this->markTestSkipped('MySQL 8.4 is required for scoped assignment locking tests.');
        }
    }

    public function test_scoped_assignment_creation_locks_the_application_before_writing(): void
    {
        $user = User::factory()->active()->create();
        $role = Role::factory()->create();
        $application = Application::factory()->create();
        $transactionLevels = [];

        RoleAssignment::creating(static function () use (&$transactionLevels): void {
            $transactionLevels[] = DB::transactionLevel();
        });

        $queries = $this->recordQueries(static fn (): RoleAssignment => RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => $application->id,
        ]));

        self::assertSame([$this->outerTransactionLevel + 1], $transactionLevels);
        $this->assertApplicationLockPrecedesAssignmentWrite($queries, $application->id, 'insert into role_assignments');
    }

    public function test_scoped_assignment_reactivation_locks_the_application_before_writing(): void
    {
        $application = Application::factory()->create();
        $assignment = RoleAssignment::factory()->revoked()->create(['application_id' => $application->id]);
        $transactionLevels = [];

        RoleAssignment::updating(static function () use (&$transactionLevels): void {
            $transactionLevels[] = DB::transactionLevel();
        });

        $queries = $this->recordQueries(static function () use ($assignment): void {
            $assignment->update(['revoked_at' => null]);
        });

        self::assertSame([$this->outerTransactionLevel + 1], $transactionLevels);
        $this->assertApplicationLockPrecedesAssignmentWrite($queries, $application->id, 'update role_assignments');
    }

    public function test_scoped_assignment_rescope_locks_the_target_application_before_writing(): void
    {
        $source = Application::factory()->create();
        $target = Application::factory()->create();
        $assignment = RoleAssignment::factory()->create(['application_id' => $source->id]);
        $transactionLevels = [];

        RoleAssignment::updating(static function () use (&$transactionLevels): void {
            $transactionLevels[] = DB::transactionLevel();
        });

        $queries = $this->recordQueries(static function () use ($assignment, $target): void {
            $assignment->update(['application_id' => $target->id]);
        });

        self::assertSame([$this->outerTransactionLevel + 1], $transactionLevels);
        $this->assertApplicationLockPrecedesAssignmentWrite($queries, $target->id, 'update role_assignments');
    }

    private int $outerTransactionLevel;

    /**
     * @template TReturn
     *
     * @param  callable(): TReturn  $operation
     * @return list<QueryExecuted>
     */
    private function recordQueries(callable $operation): array
    {
        $queries = [];
        $this->outerTransactionLevel = DB::transactionLevel();

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query;
        });

        $operation();

        return $queries;
    }

    /** @param list<QueryExecuted> $queries */
    private function assertApplicationLockPrecedesAssignmentWrite(
        array $queries,
        int $applicationId,
        string $writePrefix,
    ): void {
        $lockIndex = null;
        $writeIndex = null;

        foreach ($queries as $index => $query) {
            $sql = strtolower(str_replace('`', '', $query->sql));

            if (str_contains($sql, 'from applications')
                && str_contains($sql, 'for update')
                && in_array($applicationId, $query->bindings, true)) {
                $lockIndex ??= $index;
            }

            if (str_starts_with($sql, $writePrefix)) {
                $writeIndex ??= $index;
            }
        }

        self::assertNotNull($lockIndex, 'The target application row was not locked for update.');
        self::assertNotNull($writeIndex, 'The role assignment write query was not executed.');
        self::assertLessThan($writeIndex, $lockIndex, 'The application must be locked before the assignment write.');
    }
}
