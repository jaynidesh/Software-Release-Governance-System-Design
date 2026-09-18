<?php

declare(strict_types=1);

namespace App\Application\Foundation;

final class EnvironmentValidator
{
    private const array MANDATORY_PRIVILEGED_PERMISSIONS = [
        'admin.',
        'production.approve',
        'signoff.production',
        'maker_checker.override.approve',
    ];

    /** @param array<string, mixed> $settings */
    public function validate(array $settings): void
    {
        $errors = [];
        $production = ($settings['environment'] ?? null) === 'production';

        if (($settings['key'] ?? '') === '') {
            $errors[] = 'APP_KEY is required.';
        }
        if (($settings['timezone'] ?? null) !== 'UTC') {
            $errors[] = 'APP_TIMEZONE must be UTC.';
        }
        if (($settings['database_connection'] ?? null) !== 'mysql') {
            $errors[] = 'DB_CONNECTION must be mysql.';
        }
        if (($settings['database_name'] ?? '') === '') {
            $errors[] = 'DB_DATABASE is required.';
        }
        if (($settings['database_username'] ?? '') === '') {
            $errors[] = 'DB_USERNAME is required.';
        }
        if ($production && ($settings['debug'] ?? false) === true) {
            $errors[] = 'APP_DEBUG must be false in production.';
        }
        if ($production && ! str_starts_with((string) ($settings['url'] ?? ''), 'https://')) {
            $errors[] = 'APP_URL must use HTTPS in production.';
        }
        if ($production && ($settings['secure_cookie'] ?? false) !== true) {
            $errors[] = 'SESSION_SECURE_COOKIE must be true in production.';
        }

        if (($settings['auth_provider'] ?? null) !== 'email_otp') {
            $errors[] = 'AUTH_PROVIDER must be email_otp.';
        }
        if (($settings['otp_channel'] ?? null) !== 'mail') {
            $errors[] = 'AUTH_OTP_CHANNEL must be mail.';
        }
        if (! in_array($settings['otp_digits'] ?? null, [6, 8], true)) {
            $errors[] = 'AUTH_OTP_DIGITS must be 6 or 8.';
        }

        $this->validateRange($errors, $settings, 'otp_ttl_minutes', 'AUTH_OTP_TTL_MINUTES', 2, 15);
        $this->validateRange($errors, $settings, 'otp_max_attempts', 'AUTH_OTP_MAX_ATTEMPTS', 3, 10);
        $this->validateRange($errors, $settings, 'otp_request_limit', 'AUTH_OTP_REQUEST_LIMIT', 1, 10);
        $this->validateRange($errors, $settings, 'otp_ip_request_limit', 'AUTH_OTP_IP_REQUEST_LIMIT', 10, 300);
        $this->validateRange($errors, $settings, 'otp_request_window_minutes', 'AUTH_OTP_REQUEST_WINDOW_MINUTES', 5, 60);
        $this->validateRange($errors, $settings, 'otp_resend_seconds', 'AUTH_OTP_RESEND_SECONDS', 30, 300);
        $this->validateRange($errors, $settings, 'challenge_retention_hours', 'AUTH_CHALLENGE_RETENTION_HOURS', 1, 168);
        $this->validateRange($errors, $settings, 'invitation_ttl_days', 'AUTH_INVITATION_TTL_DAYS', 1, 30);
        $this->validateRange($errors, $settings, 'lockout_attempts', 'AUTH_LOCKOUT_ATTEMPTS', 3, 10);
        $this->validateRange($errors, $settings, 'lockout_window_minutes', 'AUTH_LOCKOUT_WINDOW_MINUTES', 5, 60);
        $this->validateRange($errors, $settings, 'lockout_minutes', 'AUTH_LOCKOUT_MINUTES', 5, 1440);
        $this->validateRange($errors, $settings, 'session_inactivity_minutes', 'AUTH_SESSION_INACTIVITY_MINUTES', 5, 60);
        $this->validateRange($errors, $settings, 'session_absolute_minutes', 'AUTH_SESSION_ABSOLUTE_MINUTES', 30, 1440);
        $this->validateRange($errors, $settings, 'privileged_reauth_minutes', 'AUTH_PRIVILEGED_REAUTH_MINUTES', 1, 30);
        $this->validateRange($errors, $settings, 'totp_window', 'AUTH_TOTP_WINDOW', 0, 1);
        $this->validateRange($errors, $settings, 'totp_recovery_code_count', 'AUTH_TOTP_RECOVERY_CODE_COUNT', 8, 16);
        $this->validateRange($errors, $settings, 'totp_recovery_code_length', 'AUTH_TOTP_RECOVERY_CODE_LENGTH', 10, 20);
        $this->validateRange($errors, $settings, 'unconfirmed_mfa_ttl_minutes', 'AUTH_UNCONFIRMED_MFA_TTL_MINUTES', 5, 120);
        $this->validateRange($errors, $settings, 'pending_auth_ttl_minutes', 'AUTH_PENDING_AUTH_TTL_MINUTES', 2, 15);
        $this->validateRange($errors, $settings, 'event_retention_days', 'AUTH_EVENT_RETENTION_DAYS', 365, 3650);

        $otpPepper = $settings['otp_pepper'] ?? null;
        if ($production && (! is_string($otpPepper) || strlen($otpPepper) < 32 || $this->appKeyMatchesPepper((string) ($settings['key'] ?? ''), $otpPepper))) {
            $errors[] = 'AUTH_OTP_PEPPER must be an independent secret of at least 32 bytes in production.';
        }
        if (($settings['session_driver'] ?? null) !== 'database') {
            $errors[] = 'SESSION_DRIVER must be database.';
        }
        if (($settings['session_encrypt'] ?? false) !== true) {
            $errors[] = 'SESSION_ENCRYPT must be true.';
        }
        if (($settings['queue_connection'] ?? null) !== 'database') {
            $errors[] = 'QUEUE_CONNECTION must be database.';
        }
        if (($settings['session_lifetime'] ?? null) !== ($settings['session_inactivity_minutes'] ?? null)) {
            $errors[] = 'SESSION_LIFETIME must equal AUTH_SESSION_INACTIVITY_MINUTES.';
        }
        if (is_int($settings['session_absolute_minutes'] ?? null)
            && is_int($settings['session_inactivity_minutes'] ?? null)
            && $settings['session_absolute_minutes'] <= $settings['session_inactivity_minutes']) {
            $errors[] = 'AUTH_SESSION_ABSOLUTE_MINUTES must be greater than AUTH_SESSION_INACTIVITY_MINUTES.';
        }
        if (is_int($settings['privileged_reauth_minutes'] ?? null)
            && is_int($settings['session_inactivity_minutes'] ?? null)
            && $settings['privileged_reauth_minutes'] > $settings['session_inactivity_minutes']) {
            $errors[] = 'AUTH_PRIVILEGED_REAUTH_MINUTES must not exceed AUTH_SESSION_INACTIVITY_MINUTES.';
        }
        if (! is_string($settings['totp_issuer'] ?? null)
            || trim($settings['totp_issuer']) === ''
            || strlen($settings['totp_issuer']) > 100) {
            $errors[] = 'AUTH_TOTP_ISSUER must be a non-empty display string of at most 100 bytes.';
        }
        if (! is_string($settings['security_queue'] ?? null)
            || trim($settings['security_queue']) === ''
            || strlen($settings['security_queue']) > 255) {
            $errors[] = 'AUTH_SECURITY_QUEUE must be a non-empty queue name of at most 255 bytes.';
        }

        $privilegedPermissions = $settings['privileged_permissions'] ?? null;
        if (! is_array($privilegedPermissions)
            || array_diff(self::MANDATORY_PRIVILEGED_PERMISSIONS, $privilegedPermissions) !== []) {
            $errors[] = 'AUTH_ADDITIONAL_PRIVILEGED_PERMISSIONS cannot remove mandatory privileged permissions.';
        }

        $additionalPermissions = $settings['additional_privileged_permissions'] ?? null;
        $knownPermissions = $settings['known_permissions'] ?? [];
        if (! is_array($additionalPermissions)
            || ! is_array($knownPermissions)
            || ! $this->additionalPermissionsAreValid($additionalPermissions, $knownPermissions)) {
            $errors[] = 'AUTH_ADDITIONAL_PRIVILEGED_PERMISSIONS must contain existing exact permission codes or trailing-dot prefixes.';
        }

        if ($errors !== []) {
            throw new InvalidEnvironmentConfiguration($errors);
        }
    }

    /**
     * @param  list<string>  $errors
     * @param  array<string, mixed>  $settings
     */
    private function validateRange(array &$errors, array $settings, string $key, string $environmentKey, int $minimum, int $maximum): void
    {
        $value = $settings[$key] ?? null;

        if (! is_int($value) || $value < $minimum || $value > $maximum) {
            $errors[] = sprintf('%s must be between %d and %d.', $environmentKey, $minimum, $maximum);
        }
    }

    /**
     * @param  array<mixed>  $additionalPermissions
     * @param  array<mixed>  $knownPermissions
     */
    private function additionalPermissionsAreValid(array $additionalPermissions, array $knownPermissions): bool
    {
        foreach ($additionalPermissions as $permission) {
            if (! is_string($permission) || trim($permission) !== $permission) {
                return false;
            }

            if (str_ends_with($permission, '.')) {
                if (! array_any($knownPermissions, static fn (mixed $known): bool => is_string($known) && str_starts_with($known, $permission))) {
                    return false;
                }

                continue;
            }

            if (! in_array($permission, $knownPermissions, true)) {
                return false;
            }
        }

        return true;
    }

    private function appKeyMatchesPepper(string $appKey, string $otpPepper): bool
    {
        if (hash_equals($appKey, $otpPepper)) {
            return true;
        }

        if (! str_starts_with($appKey, 'base64:')) {
            return false;
        }

        $decodedKey = base64_decode(substr($appKey, 7), true);

        return is_string($decodedKey) && hash_equals($decodedKey, $otpPepper);
    }
}
