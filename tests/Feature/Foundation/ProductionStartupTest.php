<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Symfony\Component\Process\Process;
use Tests\TestCase;

final class ProductionStartupTest extends TestCase
{
    public function test_http_and_worker_bootstrap_reject_unsafe_identity_settings_with_or_without_config_cache(): void
    {
        foreach ([false, true] as $cached) {
            foreach (['http', 'worker'] as $runtime) {
                foreach (['AUTH_OTP_PEPPER' => '', 'AUTH_OTP_DIGITS' => '1'] as $key => $value) {
                    $cache = tempnam(sys_get_temp_dir(), 'identity-config-');
                    self::assertIsString($cache);
                    unlink($cache);
                    $environment = $this->environment($cache) + [$key => $value];
                    $environment[$key] = $value;
                    try {
                        if ($cached) {
                            $build = new Process([PHP_BINARY, 'artisan', 'config:cache'], base_path(), $environment);
                            $build->mustRun();
                        }
                        $script = $runtime === 'http'
                            ? 'require "vendor/autoload.php"; $app = require "bootstrap/app.php"; $app->make(Illuminate\\Contracts\\Http\\Kernel::class)->bootstrap(); echo "STARTED";'
                            : 'require "vendor/autoload.php"; $_SERVER["argv"] = ["artisan", "queue:work", "--once"]; $app = require "bootstrap/app.php"; $app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap(); echo "STARTED";';
                        $environment['APP_RUNNING_IN_CONSOLE'] = $runtime === 'http' ? 'false' : 'true';
                        $process = new Process([PHP_BINARY, '-r', $script], base_path(), $environment);
                        $process->run();
                        self::assertFalse($process->isSuccessful(), "$runtime cached=$cached accepted $key");
                        self::assertStringNotContainsString('STARTED', $process->getOutput());
                        self::assertStringContainsString($key, $process->getOutput().$process->getErrorOutput());
                    } finally {
                        if (is_file($cache)) {
                            unlink($cache);
                        }
                    }
                }
            }
        }
    }

    public function test_valid_production_bootstrap_and_safe_setup_command_remain_available(): void
    {
        $environment = $this->environment(sys_get_temp_dir().'/identity-no-config-'.bin2hex(random_bytes(8)));
        $script = 'require "vendor/autoload.php"; $app = require "bootstrap/app.php"; $app->make(Illuminate\\Contracts\\Http\\Kernel::class)->bootstrap(); echo "STARTED";';
        $environment['APP_RUNNING_IN_CONSOLE'] = 'false';
        $process = new Process([PHP_BINARY, '-r', $script], base_path(), $environment);
        $process->mustRun();
        self::assertStringContainsString('STARTED', $process->getOutput());
        $environment['APP_RUNNING_IN_CONSOLE'] = 'true';
        $environment['AUTH_OTP_PEPPER'] = '';
        $process = new Process([PHP_BINARY, 'artisan', 'list', '--raw'], base_path(), $environment);
        $process->mustRun();
        self::assertStringContainsString('environment:validate', $process->getOutput());
    }

    /** @return array<string, string> */
    private function environment(string $cache): array
    {
        return [
            'APP_ENV' => 'production', 'APP_DEBUG' => 'false',
            'APP_KEY' => 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            'APP_URL' => 'https://identity.example.test', 'APP_CONFIG_CACHE' => $cache,
            'AUTH_OTP_PEPPER' => 'production-bootstrap-fixture-pepper-only', 'AUTH_OTP_DIGITS' => '6',
            'DB_CONNECTION' => 'mysql', 'DB_DATABASE' => 'sbmtag_test', 'DB_USERNAME' => 'sbmtag_test',
            'SESSION_DRIVER' => 'database', 'SESSION_ENCRYPT' => 'true', 'SESSION_SECURE_COOKIE' => 'true',
            'SESSION_LIFETIME' => '15', 'QUEUE_CONNECTION' => 'database', 'LOG_CHANNEL' => 'stderr',
        ];
    }
}
