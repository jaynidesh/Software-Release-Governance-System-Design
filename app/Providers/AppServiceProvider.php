<?php

declare(strict_types=1);

namespace App\Providers;

use App\Contracts\Foundation\ReadinessCheck;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\AuthorizationCatalog;
use App\Models\Application;
use App\Models\User;
use App\Policies\ApplicationPolicy;
use App\Services\Foundation\DatabaseReadinessCheck;
use App\Services\Identity\EloquentAuthorizationService;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Pagination\Paginator;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->bind(ReadinessCheck::class, DatabaseReadinessCheck::class);
        $this->app->bind(AuthorizationService::class, EloquentAuthorizationService::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Model::preventLazyLoading(! $this->app->isProduction());
        Paginator::useBootstrapFive();
        Gate::policy(Application::class, ApplicationPolicy::class);

        $app = $this->app;

        foreach (array_keys(AuthorizationCatalog::permissions()) as $permission) {
            Gate::define(
                $permission,
                static fn (
                    User $user,
                    ?Application $application = null,
                    bool $requiresFreshReauthentication = false,
                ): bool => $app->make(AuthorizationService::class)->allows(
                    $user,
                    $permission,
                    $application,
                    $requiresFreshReauthentication,
                ),
            );
        }
    }
}
