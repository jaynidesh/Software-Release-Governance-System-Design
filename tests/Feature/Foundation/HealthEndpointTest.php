<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use App\Contracts\Foundation\ReadinessCheck;
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
}
