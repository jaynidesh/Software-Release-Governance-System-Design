<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Application\Foundation\EnvironmentValidator;
use App\Application\Foundation\InvalidEnvironmentConfiguration;
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
