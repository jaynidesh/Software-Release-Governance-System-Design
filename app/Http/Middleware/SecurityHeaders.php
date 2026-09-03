<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $response->headers->set('Content-Security-Policy', $this->contentSecurityPolicy());
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        if (app()->environment('production') && $request->isSecure()) {
            $response->headers->set('Strict-Transport-Security', config('security.hsts'));
        }

        return $response;
    }

    private function contentSecurityPolicy(): string
    {
        $policy = (string) config('security.content_security_policy');

        if (! app()->environment('local')) {
            return $policy;
        }

        $viteOrigin = (string) config('security.vite_dev_server_origin');
        $viteWebSocketOrigin = str_replace(['https://', 'http://'], ['wss://', 'ws://'], $viteOrigin);

        return str_replace(
            ["style-src 'self'", "script-src 'self'"],
            ["style-src 'self' 'unsafe-inline' {$viteOrigin}", "script-src 'self' {$viteOrigin}"],
            $policy,
        )."; connect-src 'self' {$viteOrigin} {$viteWebSocketOrigin}";
    }
}
