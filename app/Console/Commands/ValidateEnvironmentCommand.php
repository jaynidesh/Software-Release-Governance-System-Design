<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Application\Foundation\EnvironmentConfiguration;
use App\Application\Foundation\InvalidEnvironmentConfiguration;
use Illuminate\Console\Command;

final class ValidateEnvironmentCommand extends Command
{
    protected $signature = 'environment:validate';

    protected $description = 'Validate deployment-critical application configuration';

    public function handle(EnvironmentConfiguration $configuration): int
    {
        try {
            $configuration->validate();
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
