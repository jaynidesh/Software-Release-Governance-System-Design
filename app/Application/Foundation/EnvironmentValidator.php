<?php

declare(strict_types=1);

namespace App\Application\Foundation;

final class EnvironmentValidator
{
    /** @param array<string, bool|string|null> $settings */
    public function validate(array $settings): void
    {
        $errors = [];
        $production = ($settings['environment'] ?? null) === 'production';

        if (($settings['key'] ?? '') === '') $errors[] = 'APP_KEY is required.';
        if (($settings['timezone'] ?? null) !== 'UTC') $errors[] = 'APP_TIMEZONE must be UTC.';
        if (($settings['database_connection'] ?? null) !== 'mysql') $errors[] = 'DB_CONNECTION must be mysql.';
        if (($settings['database_name'] ?? '') === '') $errors[] = 'DB_DATABASE is required.';
        if (($settings['database_username'] ?? '') === '') $errors[] = 'DB_USERNAME is required.';
        if ($production && ($settings['debug'] ?? false) === true) $errors[] = 'APP_DEBUG must be false in production.';
        if ($production && ! str_starts_with((string) ($settings['url'] ?? ''), 'https://')) $errors[] = 'APP_URL must use HTTPS in production.';
        if ($production && ($settings['secure_cookie'] ?? false) !== true) $errors[] = 'SESSION_SECURE_COOKIE must be true in production.';

        if ($errors !== []) throw new InvalidEnvironmentConfiguration($errors);
    }
}
