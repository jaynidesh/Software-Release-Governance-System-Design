<?php

declare(strict_types=1);

namespace Tests\Unit\Identity;

use App\Application\Foundation\EnvironmentValidator;
use App\Application\Foundation\InvalidEnvironmentConfiguration;
use Tests\TestCase;

final class IdentityConfigurationTest extends TestCase
{
    public function test_identity_configuration_has_documented_defaults(): void
    {
        self::assertSame([
            'provider' => 'email_otp',
            'otp' => [
                'channel' => 'mail',
                'pepper' => '',
                'digits' => 6,
                'ttl_minutes' => 10,
                'max_attempts' => 5,
                'request_limit' => 3,
                'ip_request_limit' => 30,
                'request_window_minutes' => 15,
                'resend_seconds' => 60,
            ],
            'challenge_retention_hours' => 24,
            'invitation_ttl_days' => 7,
            'lockout' => [
                'attempts' => 5,
                'window_minutes' => 15,
                'minutes' => 30,
            ],
            'session' => [
                'inactivity_minutes' => 15,
                'absolute_minutes' => 480,
            ],
            'privileged_reauth_minutes' => 10,
            'totp' => [
                'issuer' => config('app.name'),
                'window' => 1,
                'recovery_code_count' => 10,
                'recovery_code_length' => 12,
                'unconfirmed_ttl_minutes' => 30,
            ],
            'pending_auth_ttl_minutes' => 10,
            'privileged_permissions' => [
                'admin.',
                'production.approve',
                'signoff.production',
                'maker_checker.override.approve',
            ],
            'additional_privileged_permissions' => [],
            'security_queue' => 'security',
            'event_retention_days' => 2555,
            'administration' => [
                'per_page' => 15,
            ],
        ], config('identity'));
    }

    public function test_documented_range_boundaries_are_accepted(): void
    {
        foreach ($this->rangeSettings() as $name => [$minimum, $maximum]) {
            $settings = $this->secureSettings();
            $settings[$name] = $minimum;
            $this->alignDependentSessionSettings($settings, $name);
            (new EnvironmentValidator)->validate($settings);

            $settings[$name] = $maximum;
            $this->alignDependentSessionSettings($settings, $name);
            (new EnvironmentValidator)->validate($settings);
        }

        self::assertTrue(true);
    }

    public function test_values_outside_every_documented_range_are_rejected(): void
    {
        foreach ($this->rangeSettings() as $name => [$minimum, $maximum]) {
            $this->assertInvalidSetting($name, $minimum - 1);
            $this->assertInvalidSetting($name, $maximum + 1);
        }
    }

    public function test_only_documented_otp_adapters_and_digit_counts_are_accepted(): void
    {
        (new EnvironmentValidator)->validate($this->secureSettings());
        (new EnvironmentValidator)->validate(array_replace($this->secureSettings(), ['otp_digits' => 8]));

        $this->assertInvalidSetting('auth_provider', 'sso');
        $this->assertInvalidSetting('otp_channel', 'sms');
        $this->assertInvalidSetting('otp_digits', 7);
    }

    public function test_mandatory_privileged_permission_baseline_cannot_be_removed(): void
    {
        foreach (['admin.', 'production.approve', 'signoff.production', 'maker_checker.override.approve'] as $permission) {
            $settings = $this->secureSettings();
            $settings['privileged_permissions'] = array_values(array_diff($settings['privileged_permissions'], [$permission]));

            $this->expectValidationFailure($settings, 'AUTH_ADDITIONAL_PRIVILEGED_PERMISSIONS cannot remove mandatory privileged permissions.');
        }
    }

    public function test_additional_privileged_permissions_must_be_canonical_exact_codes_or_prefixes(): void
    {
        foreach ([['release.edit'], ['release.'], ['admin.users', 'production.']] as $additional) {
            $settings = $this->secureSettings();
            $settings['additional_privileged_permissions'] = $additional;
            $settings['privileged_permissions'] = array_values(array_unique([
                ...$settings['privileged_permissions'],
                ...$additional,
            ]));

            (new EnvironmentValidator)->validate($settings);
        }

        foreach ([['*'], ['release.*'], [' Release.edit'], ['release edit'], ['admin']] as $additional) {
            $this->assertInvalidSetting('additional_privileged_permissions', $additional);
        }
    }

    public function test_production_requires_an_independent_otp_pepper_of_at_least_32_bytes(): void
    {
        $this->assertInvalidSetting('otp_pepper', str_repeat('p', 31));

        (new EnvironmentValidator)->validate(array_replace($this->secureSettings(), [
            'otp_pepper' => str_repeat('p', 32),
        ]));
    }

    public function test_production_rejects_the_decoded_application_key_as_the_otp_pepper(): void
    {
        $applicationKeyBytes = str_repeat('k', 32);
        $settings = array_replace($this->secureSettings(), [
            'key' => 'base64:'.base64_encode($applicationKeyBytes),
            'otp_pepper' => $applicationKeyBytes,
        ]);

        $this->expectValidationFailure(
            $settings,
            'AUTH_OTP_PEPPER must be an independent secret of at least 32 bytes in production.',
        );
    }

    public function test_non_production_may_use_a_blank_otp_pepper(): void
    {
        (new EnvironmentValidator)->validate(array_replace($this->secureSettings(), [
            'environment' => 'testing',
            'otp_pepper' => '',
        ]));

        self::assertTrue(true);
    }

    public function test_session_lifetime_must_equal_identity_inactivity_limit(): void
    {
        $this->assertInvalidSetting('session_lifetime', 16);
    }

    public function test_absolute_session_limit_must_exceed_inactivity_limit(): void
    {
        $this->assertInvalidSetting('session_absolute_minutes', 15);
    }

    public function test_privileged_reauthentication_limit_cannot_exceed_inactivity_limit(): void
    {
        $this->assertInvalidSetting('privileged_reauth_minutes', 16);
    }

    public function test_identity_controls_require_database_backed_encrypted_sessions_and_queue(): void
    {
        $this->assertInvalidSetting('session_driver', 'cookie');
        $this->assertInvalidSetting('session_encrypt', false);
        $this->assertInvalidSetting('queue_connection', 'sync');
        $this->assertInvalidSetting('totp_issuer', '');
        $this->assertInvalidSetting('security_queue', '');
    }

    /** @return array<string, array{int, int}> */
    private function rangeSettings(): array
    {
        return [
            'otp_ttl_minutes' => [2, 15],
            'otp_max_attempts' => [3, 10],
            'otp_request_limit' => [1, 10],
            'otp_ip_request_limit' => [10, 300],
            'otp_request_window_minutes' => [5, 60],
            'otp_resend_seconds' => [30, 300],
            'challenge_retention_hours' => [1, 168],
            'invitation_ttl_days' => [1, 30],
            'lockout_attempts' => [3, 10],
            'lockout_window_minutes' => [5, 60],
            'lockout_minutes' => [5, 1440],
            'session_inactivity_minutes' => [5, 60],
            'session_absolute_minutes' => [30, 1440],
            'privileged_reauth_minutes' => [1, 30],
            'totp_window' => [0, 1],
            'totp_recovery_code_count' => [8, 16],
            'totp_recovery_code_length' => [10, 20],
            'unconfirmed_mfa_ttl_minutes' => [5, 120],
            'pending_auth_ttl_minutes' => [2, 15],
            'event_retention_days' => [365, 3650],
            'admin_per_page' => [5, 100],
        ];
    }

    /** @return array<string, bool|int|string|list<string>|null> */
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
            'known_permissions' => [
                'admin.users', 'release.edit', 'production.approve', 'production.deploy',
                'signoff.production', 'maker_checker.override.approve',
            ],
            'additional_privileged_permissions' => [], 'queue_connection' => 'database',
            'security_queue' => 'security', 'event_retention_days' => 2555,
            'admin_per_page' => 15,
        ];
    }

    /** @param array<string, bool|int|string|list<string>|null> $settings */
    private function alignDependentSessionSettings(array &$settings, string $name): void
    {
        if ($name === 'session_inactivity_minutes') {
            $settings['session_lifetime'] = $settings[$name];
            $settings['session_absolute_minutes'] = max(480, ((int) $settings[$name]) + 1);
            $settings['privileged_reauth_minutes'] = min(10, (int) $settings[$name]);
        }

        if ($name === 'session_absolute_minutes' && $settings[$name] <= $settings['session_inactivity_minutes']) {
            $settings['session_inactivity_minutes'] = 5;
            $settings['session_lifetime'] = 5;
        }

        if ($name === 'privileged_reauth_minutes' && $settings[$name] > $settings['session_inactivity_minutes']) {
            $settings['session_inactivity_minutes'] = 60;
            $settings['session_lifetime'] = 60;
        }
    }

    private function assertInvalidSetting(string $name, bool|int|string|array $value): void
    {
        $this->expectValidationFailure(array_replace($this->secureSettings(), [$name => $value]));
    }

    /** @param array<string, bool|int|string|list<string>|null> $settings */
    private function expectValidationFailure(array $settings, ?string $expectedError = null): void
    {
        try {
            (new EnvironmentValidator)->validate($settings);
            self::fail('Expected invalid identity configuration.');
        } catch (InvalidEnvironmentConfiguration $exception) {
            if ($expectedError !== null) {
                self::assertContains($expectedError, $exception->errors);
            } else {
                self::assertNotSame([], $exception->errors);
            }
        }
    }
}
