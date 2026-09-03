<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Tests\TestCase;

final class ProductionConfigurationTest extends TestCase
{
    public function test_security_relevant_defaults_are_explicit(): void
    {
        self::assertSame('UTC', config('app.timezone'));
        self::assertSame('mysql', config('database.default'));
        self::assertTrue((bool) config('session.encrypt'));
        self::assertTrue((bool) config('session.http_only'));
        self::assertSame('lax', config('session.same_site'));
        self::assertSame('database', config('queue.default'));
    }
}
