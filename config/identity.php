<?php

declare(strict_types=1);

$additionalPrivilegedPermissions = array_values(array_filter(array_map(
    static fn (string $permission): string => trim($permission),
    explode(',', (string) env('AUTH_ADDITIONAL_PRIVILEGED_PERMISSIONS', '')),
)));

$mandatoryPrivilegedPermissions = [
    'admin.',
    'production.approve',
    'signoff.production',
    'maker_checker.override.approve',
];

return [
    'provider' => env('AUTH_PROVIDER', 'email_otp'),
    'otp' => [
        'channel' => env('AUTH_OTP_CHANNEL', 'mail'),
        'pepper' => env('AUTH_OTP_PEPPER', ''),
        'digits' => (int) env('AUTH_OTP_DIGITS', 6),
        'ttl_minutes' => (int) env('AUTH_OTP_TTL_MINUTES', 10),
        'max_attempts' => (int) env('AUTH_OTP_MAX_ATTEMPTS', 5),
        'request_limit' => (int) env('AUTH_OTP_REQUEST_LIMIT', 3),
        'ip_request_limit' => (int) env('AUTH_OTP_IP_REQUEST_LIMIT', 30),
        'request_window_minutes' => (int) env('AUTH_OTP_REQUEST_WINDOW_MINUTES', 15),
        'resend_seconds' => (int) env('AUTH_OTP_RESEND_SECONDS', 60),
    ],
    'challenge_retention_hours' => (int) env('AUTH_CHALLENGE_RETENTION_HOURS', 24),
    'invitation_ttl_days' => (int) env('AUTH_INVITATION_TTL_DAYS', 7),
    'lockout' => [
        'attempts' => (int) env('AUTH_LOCKOUT_ATTEMPTS', 5),
        'window_minutes' => (int) env('AUTH_LOCKOUT_WINDOW_MINUTES', 15),
        'minutes' => (int) env('AUTH_LOCKOUT_MINUTES', 30),
    ],
    'session' => [
        'inactivity_minutes' => (int) env('AUTH_SESSION_INACTIVITY_MINUTES', 15),
        'absolute_minutes' => (int) env('AUTH_SESSION_ABSOLUTE_MINUTES', 480),
    ],
    'privileged_reauth_minutes' => (int) env('AUTH_PRIVILEGED_REAUTH_MINUTES', 10),
    'totp' => [
        'issuer' => env('AUTH_TOTP_ISSUER', env('APP_NAME', 'Laravel')),
        'window' => (int) env('AUTH_TOTP_WINDOW', 1),
        'recovery_code_count' => (int) env('AUTH_TOTP_RECOVERY_CODE_COUNT', 10),
        'recovery_code_length' => (int) env('AUTH_TOTP_RECOVERY_CODE_LENGTH', 12),
        'unconfirmed_ttl_minutes' => (int) env('AUTH_UNCONFIRMED_MFA_TTL_MINUTES', 30),
    ],
    'pending_auth_ttl_minutes' => (int) env('AUTH_PENDING_AUTH_TTL_MINUTES', 10),
    'privileged_permissions' => array_values(array_unique([
        ...$mandatoryPrivilegedPermissions,
        ...$additionalPrivilegedPermissions,
    ])),
    'additional_privileged_permissions' => $additionalPrivilegedPermissions,
    'security_queue' => env('AUTH_SECURITY_QUEUE', 'security'),
    'event_retention_days' => (int) env('AUTH_EVENT_RETENTION_DAYS', 2555),
    'administration' => [
        'per_page' => (int) env('AUTH_ADMIN_PER_PAGE', 15),
    ],
];
