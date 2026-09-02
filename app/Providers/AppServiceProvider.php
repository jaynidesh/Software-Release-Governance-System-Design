<?php

namespace App\Providers;

use App\Contracts\Foundation\ReadinessCheck;
use App\Services\Foundation\DatabaseReadinessCheck;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->bind(ReadinessCheck::class, DatabaseReadinessCheck::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
