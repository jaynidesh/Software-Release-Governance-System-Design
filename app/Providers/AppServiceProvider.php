<?php

declare(strict_types=1);

namespace App\Providers;

use App\Application\Foundation\EnvironmentConfiguration;
use App\Application\Identity\Sessions\CreateAuthenticatedSession;
use App\Contracts\Foundation\ReadinessCheck;
use App\Contracts\Identity\AuthenticatedSessionCreator;
use App\Contracts\Identity\AuthorizationService;
use App\Contracts\Identity\OtpDelivery;
use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Contracts\Identity\TotpVerifier;
use App\Domain\Identity\AuthorizationCatalog;
use App\Infrastructure\Database\IdentityMySqlConnection;
use App\Infrastructure\Database\IdentitySqliteConnection;
use App\Models\Application;
use App\Models\AuthChallenge;
use App\Models\User;
use App\Notifications\Identity\EmailOtpNotification;
use App\Policies\ApplicationPolicy;
use App\Services\Foundation\DatabaseReadinessCheck;
use App\Services\Identity\EloquentAuthorizationService;
use App\Services\Identity\EmailOtpAuthenticationProvider;
use App\Services\Identity\IdentityMutationBoundary;
use App\Services\Identity\LaravelOtpDelivery;
use App\Services\Identity\OtpDeliveryFailureReporter;
use App\Services\Identity\OtpPhpTotpVerifier;
use App\Services\Identity\SafeOtpMailChannel;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Channels\MailChannel;
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
        // Secret-bearing framework arguments must not survive in replacement exception traces.
        ini_set('zend.exception_ignore_args', '1');
        if (! filter_var(ini_get('zend.exception_ignore_args'), FILTER_VALIDATE_BOOLEAN)) {
            throw new \LogicException('Exception argument capture must be disabled.');
        }
        $this->app->scoped(IdentityMutationBoundary::class);
        $this->app->bind(MailChannel::class, SafeOtpMailChannel::class);
        Connection::resolverFor('mysql', static fn ($pdo, $database, $prefix, $config) => new IdentityMySqlConnection($pdo, $database, $prefix, $config));
        Connection::resolverFor('sqlite', static fn ($pdo, $database, $prefix, $config) => new IdentitySqliteConnection($pdo, $database, $prefix, $config));
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
        if ($this->app->isProduction()
            && ! $this->app->runningConsoleCommand([
                'list', 'help', 'about', 'key:generate', 'package:discover',
                'config:cache', 'config:clear', 'environment:validate',
            ])) {
            $this->app->make(EnvironmentConfiguration::class)->validate();
        }

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
