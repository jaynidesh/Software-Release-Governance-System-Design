<?php

declare(strict_types=1);

namespace App\Providers;

use App\Application\Identity\Sessions\CreateAuthenticatedSession;
use App\Contracts\Foundation\ReadinessCheck;
use App\Contracts\Identity\AuthenticatedSessionCreator;
use App\Contracts\Identity\AuthorizationService;
use App\Contracts\Identity\OtpDelivery;
use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Contracts\Identity\TotpVerifier;
use App\Domain\Identity\AuthorizationCatalog;
use App\Models\Application;
use App\Models\AuthChallenge;
use App\Models\User;
use App\Notifications\Identity\EmailOtpNotification;
use App\Policies\ApplicationPolicy;
use App\Services\Foundation\DatabaseReadinessCheck;
use App\Services\Identity\EloquentAuthorizationService;
use App\Services\Identity\EmailOtpAuthenticationProvider;
use App\Services\Identity\LaravelOtpDelivery;
use App\Services\Identity\OtpDeliveryFailureReporter;
use App\Services\Identity\OtpPhpTotpVerifier;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Events\NotificationFailed;
use Illuminate\Pagination\Paginator;
use Illuminate\Support\Facades\Event;
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
        $this->app->bind(AuthenticatedSessionCreator::class, CreateAuthenticatedSession::class);
        $this->app->bind(PrimaryAuthenticationProvider::class, EmailOtpAuthenticationProvider::class);
        $this->app->bind(OtpDelivery::class, LaravelOtpDelivery::class);
        $this->app->bind(TotpVerifier::class, OtpPhpTotpVerifier::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Model::preventLazyLoading(! $this->app->isProduction());
        Paginator::useBootstrapFive();
        Gate::policy(Application::class, ApplicationPolicy::class);

        Event::listen(NotificationFailed::class, function (NotificationFailed $event): void {
            if (! $event->notification instanceof EmailOtpNotification || ! $event->notifiable instanceof User) {
                return;
            }

            $challenge = AuthChallenge::query()
                ->where('public_id', $event->notification->challengeReference)
                ->first();

            if ($challenge === null) {
                return;
            }

            if ($challenge->user_id !== $event->notifiable->getKey()) {
                return;
            }

            $exception = $event->data['exception'] ?? null;
            $this->app->make(OtpDeliveryFailureReporter::class)->report(
                $event->notifiable,
                $challenge,
                $event->channel,
                $exception instanceof \Throwable ? $exception : null,
            );
        });

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
