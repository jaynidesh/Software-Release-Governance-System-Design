<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use App\Contracts\Foundation\ReadinessCheck;
use Illuminate\Session\SessionManager;
use RuntimeException;
use SessionHandlerInterface;
use Tests\TestCase;

final class HealthEndpointTest extends TestCase
{
    public function test_liveness_returns_only_a_stable_status(): void
    {
        $this->getJson('/health')->assertOk()->assertExactJson(['status' => 'ok']);
    }

    public function test_readiness_is_ok_when_dependencies_are_available(): void
    {
        $this->app->bind(ReadinessCheck::class, fn (): ReadinessCheck => new class implements ReadinessCheck
        {
            public function check(): bool
            {
                return true;
            }
        });

        $this->getJson('/ready')->assertOk()->assertExactJson(['status' => 'ready']);
    }

    public function test_readiness_hides_dependency_details_when_unavailable(): void
    {
        $this->app->bind(ReadinessCheck::class, fn (): ReadinessCheck => new class implements ReadinessCheck
        {
            public function check(): bool
            {
                return false;
            }
        });

        $this->getJson('/ready')->assertStatus(503)->assertExactJson(['status' => 'unavailable']);
    }

    public function test_liveness_remains_available_when_the_session_backend_is_down(): void
    {
        $this->configureFailingSessionBackend();

        $response = $this->getJson('/health')
            ->assertOk()
            ->assertExactJson(['status' => 'ok'])
            ->assertHeader('Content-Security-Policy', config('security.content_security_policy'));

        self::assertMatchesRegularExpression(
            '/^[0-9a-f-]{36}$/',
            (string) $response->headers->get('X-Correlation-ID'),
        );
    }

    public function test_readiness_returns_a_sanitized_response_when_session_and_database_dependencies_are_down(): void
    {
        $this->configureFailingSessionBackend();
        $this->app->bind(ReadinessCheck::class, fn (): ReadinessCheck => new class implements ReadinessCheck
        {
            public function check(): bool
            {
                return false;
            }
        });

        $response = $this->getJson('/ready')
            ->assertStatus(503)
            ->assertExactJson(['status' => 'unavailable'])
            ->assertHeader('Content-Security-Policy', config('security.content_security_policy'));

        self::assertMatchesRegularExpression(
            '/^[0-9a-f-]{36}$/',
            (string) $response->headers->get('X-Correlation-ID'),
        );
    }

    private function configureFailingSessionBackend(): void
    {
        $sessions = $this->app->make('session');
        self::assertInstanceOf(SessionManager::class, $sessions);

        $sessions->extend('failing', static fn (): SessionHandlerInterface => new class implements SessionHandlerInterface
        {
            public function open(string $path, string $name): bool
            {
                return true;
            }

            public function close(): bool
            {
                return true;
            }

            public function read(string $id): string|false
            {
                throw new RuntimeException('Session backend unavailable.');
            }

            public function write(string $id, string $data): bool
            {
                throw new RuntimeException('Session backend unavailable.');
            }

            public function destroy(string $id): bool
            {
                throw new RuntimeException('Session backend unavailable.');
            }

            public function gc(int $max_lifetime): int|false
            {
                throw new RuntimeException('Session backend unavailable.');
            }
        });

        config(['session.driver' => 'failing']);
    }
}
