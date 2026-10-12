<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Models\AuthSession;
use App\Models\User;
use App\Services\Identity\CurrentAuthSessionValidator;
use App\Support\Exceptions\AuthenticatedSessionPersistenceException;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\DatabaseSessionHandler;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Tests\TestCase;
use Throwable;

final class SessionFailurePrivacyTest extends TestCase
{
    use RefreshDatabase;

    public function test_session_lookup_query_failure_is_sanitized_before_normal_reporting(): void
    {
        $user = User::factory()->active()->create();
        $session = $this->app->make(Session::class);
        $rawId = $session->getId();
        AuthSession::addGlobalScope('query_failure', static fn ($query) => $query->whereRaw('missing_test_column = ?', [1]));
        $this->assertSafeFailure(fn () => $this->app->make(CurrentAuthSessionValidator::class)->current($user, false, false), $rawId);
    }

    public function test_payload_read_write_destroy_and_raw_batch_delete_failures_are_sanitized(): void
    {
        $session = $this->app->make(Session::class);
        $rawId = $session->getId();
        foreach (['select', 'update', 'delete'] as $operation) {
            $this->assertSafeFailure(function () use ($operation, $rawId): void {
                $query = DB::table('sessions')->where('id', $rawId)->whereRaw('missing_test_column = ?', [1]);
                match ($operation) {
                    'select' => $query->first(),
                    'update' => $query->update(['payload' => 'secret-payload']),
                    'delete' => $query->delete(),
                };
            }, $rawId);
        }
        $this->assertSafeFailure(fn () => DB::table('auth_sessions')->insert(['session_id' => $rawId, 'missing_test_column' => 1]), $rawId);
    }

    public function test_framework_session_handler_failures_do_not_retain_secret_arguments(): void
    {
        config()->set('session.table', 'unavailable_session_payloads');
        $this->app->make('session')->forgetDrivers();
        $session = $this->app->make('session')->driver();
        $rawId = str_repeat('private-session-id-', 2).'ab';
        foreach ([
            fn () => $session->getHandler()->read($rawId),
            fn () => $session->getHandler()->write($rawId, 'secret-payload'),
            fn () => $session->getHandler()->destroy($rawId),
        ] as $operation) {
            $this->assertSafeFailure($operation, $rawId);
        }
    }

    public function test_racing_initial_payload_insert_retains_the_framework_update_fallback(): void
    {
        $rawId = str_repeat('a', 40);
        $first = new DatabaseSessionHandler(DB::connection(), 'sessions', 15, $this->app);
        $competing = new DatabaseSessionHandler(DB::connection(), 'sessions', 15, $this->app);
        $inserted = false;
        DB::listen(function (QueryExecuted $query) use ($rawId, $competing, &$inserted): void {
            if (! $inserted && str_starts_with($query->sql, 'select * from')
                && str_contains($query->sql, 'sessions') && in_array($rawId, $query->bindings, true)) {
                $inserted = true;
                self::assertTrue($competing->write($rawId, 'competing-payload'));
            }
        });

        self::assertTrue($first->write($rawId, 'latest-payload'));
        self::assertTrue($inserted);
        self::assertSame(1, DB::table('sessions')->where('id', $rawId)->count());
        self::assertSame('latest-payload', base64_decode(DB::table('sessions')->where('id', $rawId)->value('payload')));
    }

    private function assertSafeFailure(callable $operation, string $rawId): void
    {
        $handler = new TestHandler;
        Log::swap(new Logger('privacy', [$handler]));
        $caught = null;
        try {
            $operation();
        } catch (Throwable $exception) {
            $caught = $exception;
        }
        self::assertNotNull($caught, 'Expected a real database query failure.');
        $this->app->make(ExceptionHandler::class)->report($caught);
        self::assertStringNotContainsString($rawId, json_encode($handler->getRecords(), JSON_THROW_ON_ERROR));
        self::assertInstanceOf(AuthenticatedSessionPersistenceException::class, $caught);
        self::assertNull($caught->getPrevious());
        self::assertSame('', $caught->getSql());
        self::assertSame([], $caught->getBindings());
        self::assertStringNotContainsString($rawId, (string) $caught);
        self::assertStringNotContainsString('secret-payload', (string) $caught);
        self::assertStringNotContainsString($rawId, json_encode($caught->getTrace(), JSON_PARTIAL_OUTPUT_ON_ERROR));
    }
}
