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

    /** @return array<string, bool|int|string|list<string>> */
    private function secureSettings(): array
    {
        return [
            'environment' => 'production', 'key' => 'base64:valid', 'debug' => false,
            'url' => 'https://release.example.test', 'timezone' => 'UTC',
            'database_connection' => 'mysql', 'database_name' => 'sbmtag',
            'database_username' => 'sbmtag_app', 'secure_cookie' => true,
            'auth_provider' => 'email_otp', 'otp_channel' => 'mail',
            'otp_pepper' => str_repeat('p', 32), 'otp_digits' => 6,
            'otp_ttl_minutes' => 10, 'otp_max_attempts' => 5,
            'otp_request_limit' => 3, 'otp_ip_request_limit' => 30,
            'otp_request_window_minutes' => 15, 'otp_resend_seconds' => 60,
            'challenge_retention_hours' => 24, 'invitation_ttl_days' => 7,
            'lockout_attempts' => 5, 'lockout_window_minutes' => 15, 'lockout_minutes' => 30,
            'session_driver' => 'database', 'session_encrypt' => true,
            'session_lifetime' => 15, 'session_inactivity_minutes' => 15,
            'session_absolute_minutes' => 480, 'privileged_reauth_minutes' => 10,
            'totp_issuer' => 'Release Governance', 'totp_window' => 1,
            'totp_recovery_code_count' => 10, 'totp_recovery_code_length' => 12,
            'unconfirmed_mfa_ttl_minutes' => 30, 'pending_auth_ttl_minutes' => 10,
            'privileged_permissions' => [
                'admin.', 'production.approve', 'signoff.production', 'maker_checker.override.approve',
            ],
            'additional_privileged_permissions' => [],
            'known_permissions' => ['admin.users'],
            'queue_connection' => 'database', 'security_queue' => 'security',
            'event_retention_days' => 2555,
            'admin_per_page' => 15,
        ];
    }
}
