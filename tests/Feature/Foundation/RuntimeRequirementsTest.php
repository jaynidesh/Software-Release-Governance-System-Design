<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Tests\TestCase;

final class RuntimeRequirementsTest extends TestCase
{
    public function test_project_declares_the_approved_dependencies(): void
    {
        $composer = json_decode(file_get_contents(base_path('composer.json')), true, flags: JSON_THROW_ON_ERROR);
        $package = json_decode(file_get_contents(base_path('package.json')), true, flags: JSON_THROW_ON_ERROR);

        self::assertSame('^8.5', $composer['require']['php']);
        self::assertSame('^13.0', $composer['require']['laravel/framework']);
        self::assertSame('^5.3.8', $package['dependencies']['bootstrap']);
        self::assertArrayHasKey('bootstrap-icons', $package['dependencies']);
        self::assertArrayHasKey('@popperjs/core', $package['dependencies']);
    }
}
