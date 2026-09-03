<?php

declare(strict_types=1);

namespace Tests\Unit\Foundation;

use App\Application\Foundation\EnvironmentValidator;
use App\Application\Foundation\InvalidEnvironmentConfiguration;
use PHPUnit\Framework\TestCase;

final class EnvironmentValidatorTest extends TestCase
{
    public function test_secure_production_settings_are_accepted(): void
    {
        (new EnvironmentValidator)->validate($this->secureSettings());
        self::assertTrue(true);
    }

    public function test_insecure_production_settings_are_rejected(): void
    {
        $settings = array_replace($this->secureSettings(), [
            'debug' => true,
            'url' => 'http://release.example.test',
            'database_connection' => 'sqlite',
            'secure_cookie' => false,
        ]);

        try {
            (new EnvironmentValidator)->validate($settings);
            self::fail('Expected invalid configuration.');
        } catch (InvalidEnvironmentConfiguration $exception) {
            self::assertSame([
                'DB_CONNECTION must be mysql.',
                'APP_DEBUG must be false in production.',
                'APP_URL must use HTTPS in production.',
                'SESSION_SECURE_COOKIE must be true in production.',
            ], $exception->errors);
        }
    }

    /** @return array<string, bool|string> */
    private function secureSettings(): array
    {
        return [
            'environment' => 'production', 'key' => 'base64:valid', 'debug' => false,
            'url' => 'https://release.example.test', 'timezone' => 'UTC',
            'database_connection' => 'mysql', 'database_name' => 'sbmtag',
            'database_username' => 'sbmtag_app', 'secure_cookie' => true,
        ];
    }
}
