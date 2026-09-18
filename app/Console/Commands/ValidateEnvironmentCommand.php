<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Application\Foundation\EnvironmentValidator;
use App\Application\Foundation\InvalidEnvironmentConfiguration;
use App\Domain\Identity\AuthorizationCatalog;
use Illuminate\Console\Command;

final class ValidateEnvironmentCommand extends Command
{
    protected $signature = 'environment:validate';

    protected $description = 'Validate deployment-critical application configuration';

    public function handle(EnvironmentValidator $validator): int
    {
        try {
            $validator->validate([
                'environment' => app()->environment(), 'key' => config('app.key'),
                'debug' => (bool) config('app.debug'), 'url' => config('app.url'),
                'timezone' => config('app.timezone'), 'database_connection' => config('database.default'),
                'database_name' => config('database.connections.mysql.database'),
                'database_username' => config('database.connections.mysql.username'),
                'secure_cookie' => (bool) config('session.secure'),
                'auth_provider' => config('identity.provider'),
                'otp_channel' => config('identity.otp.channel'),
                'otp_pepper' => config('identity.otp.pepper'),
                'otp_digits' => config('identity.otp.digits'),
                'otp_ttl_minutes' => config('identity.otp.ttl_minutes'),
                'otp_max_attempts' => config('identity.otp.max_attempts'),
                'otp_request_limit' => config('identity.otp.request_limit'),
                'otp_ip_request_limit' => config('identity.otp.ip_request_limit'),
                'otp_request_window_minutes' => config('identity.otp.request_window_minutes'),
                'otp_resend_seconds' => config('identity.otp.resend_seconds'),
                'challenge_retention_hours' => config('identity.challenge_retention_hours'),
                'invitation_ttl_days' => config('identity.invitation_ttl_days'),
                'lockout_attempts' => config('identity.lockout.attempts'),
                'lockout_window_minutes' => config('identity.lockout.window_minutes'),
                'lockout_minutes' => config('identity.lockout.minutes'),
                'session_driver' => config('session.driver'),
                'session_encrypt' => (bool) config('session.encrypt'),
                'session_lifetime' => config('session.lifetime'),
                'session_inactivity_minutes' => config('identity.session.inactivity_minutes'),
                'session_absolute_minutes' => config('identity.session.absolute_minutes'),
                'privileged_reauth_minutes' => config('identity.privileged_reauth_minutes'),
                'totp_issuer' => config('identity.totp.issuer'),
                'totp_window' => config('identity.totp.window'),
                'totp_recovery_code_count' => config('identity.totp.recovery_code_count'),
                'totp_recovery_code_length' => config('identity.totp.recovery_code_length'),
                'unconfirmed_mfa_ttl_minutes' => config('identity.totp.unconfirmed_ttl_minutes'),
                'pending_auth_ttl_minutes' => config('identity.pending_auth_ttl_minutes'),
                'privileged_permissions' => config('identity.privileged_permissions'),
                'additional_privileged_permissions' => config('identity.additional_privileged_permissions'),
                'known_permissions' => array_keys(AuthorizationCatalog::permissions()),
                'queue_connection' => config('queue.default'),
                'security_queue' => config('identity.security_queue'),
                'event_retention_days' => config('identity.event_retention_days'),
            ]);
        } catch (InvalidEnvironmentConfiguration $exception) {
            foreach ($exception->errors as $error) {
                $this->error($error);
            }

            return self::FAILURE;
        }

        $this->info('Environment configuration is valid.');

        return self::SUCCESS;
    }
}
