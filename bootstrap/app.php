<?php

use App\Http\Middleware\AssignCorrelationId;
use App\Http\Middleware\EnforceAuthenticatedSession;
use App\Http\Middleware\NoStoreAuthenticationResponse;
use App\Http\Middleware\RequireFreshReauthentication;
use App\Http\Middleware\RequirePendingAuthentication;
use App\Http\Middleware\SecurityHeaders;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->redirectGuestsTo(static fn (): string => route('home'));
        $middleware->prepend(AssignCorrelationId::class);
        $middleware->append(SecurityHeaders::class);
        $middleware->appendToGroup('web', EnforceAuthenticatedSession::class);
        $middleware->alias([
            'fresh.reauth' => RequireFreshReauthentication::class,
            'no-store.auth' => NoStoreAuthenticationResponse::class,
            'pending.auth' => RequirePendingAuthentication::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $shouldRenderJson = static fn (Request $request): bool => $request->is('api/*') || $request->expectsJson();

        $exceptions->dontFlash([
            'otp',
            'code',
            'totp',
            'recovery_code',
            'mfa_secret',
        ]);

        $exceptions->shouldRenderJsonWhen(
            $shouldRenderJson,
        );

        $exceptions->render(function (DomainRuleViolation $exception, Request $request) use ($shouldRenderJson) {
            $payload = [
                'message' => $exception->getMessage(),
                'code' => $exception->ruleCode,
                'failures' => $exception->failures,
                'correlation_id' => $request->attributes->get('correlation_id'),
            ];

            return $shouldRenderJson($request)
                ? response()->json($payload, 409)
                : back()->withErrors(['domain' => $exception->failures])->withInput();
        });

        $exceptions->respond(function (Response $response): Response {
            $request = request();
            $id = $request->attributes->get('correlation_id');

            if (is_string($id)) {
                $response->headers->set('X-Correlation-ID', $id);
            }

            if ($request->is('login') || $request->is('login/*')
                || $request->is('reauthenticate') || $request->is('reauthenticate/*')
                || $request->is('security/recovery-codes') || $request->is('security/totp')) {
                $response->headers->set('Cache-Control', 'no-store, private');
            }

            return $response;
        });
    })->create();
