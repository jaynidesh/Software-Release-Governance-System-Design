<?php

use App\Http\Middleware\AssignCorrelationId;
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
        $middleware->append(AssignCorrelationId::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );

        $exceptions->render(function (DomainRuleViolation $exception, Request $request) {
            $payload = [
                'message' => $exception->getMessage(),
                'code' => $exception->ruleCode,
                'failures' => $exception->failures,
                'correlation_id' => $request->attributes->get('correlation_id'),
            ];

            return $request->expectsJson()
                ? response()->json($payload, 409)
                : back()->withErrors(['domain' => $exception->failures])->withInput();
        });

        $exceptions->respond(function (Response $response): Response {
            $id = request()->attributes->get('correlation_id');

            if (is_string($id)) {
                $response->headers->set('X-Correlation-ID', $id);
            }

            return $response;
        });
    })->create();
