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

        $viteOrigins = $this->viteOrigins();

        if ($viteOrigins === null) {
            return $policy;
        }

        return str_replace(
            ["style-src 'self'", "script-src 'self'"],
            ["style-src 'self' 'unsafe-inline' {$viteOrigins['http']}", "script-src 'self' {$viteOrigins['http']}"],
            $policy,
        )."; connect-src 'self' {$viteOrigins['http']} {$viteOrigins['websocket']}";
    }

    /** @return array{http: string, websocket: string}|null */
    private function viteOrigins(): ?array
    {
        $configuredOrigin = (string) config('security.vite_dev_server_origin');

        if ($configuredOrigin === '' || $configuredOrigin !== trim($configuredOrigin) || preg_match('/[\s;\'\"]/', $configuredOrigin) === 1) {
            return null;
        }

        $parts = parse_url($configuredOrigin);

        if ($parts === false || array_diff(array_keys($parts), ['scheme', 'host', 'port', 'path']) !== [] || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        $path = $parts['path'] ?? '';
        $hostForValidation = trim($host, '[]');

        if (! in_array($scheme, ['http', 'https'], true) || ! in_array($path, ['', '/'], true) || ! $this->isValidHost($hostForValidation)) {
            return null;
        }

        $port = $parts['port'] ?? null;

        if ($port === 0) {
            return null;
        }

        $canonicalHost = str_contains($hostForValidation, ':') ? "[{$hostForValidation}]" : $hostForValidation;
        $canonicalPort = $port === null || ($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443) ? '' : ":{$port}";
        $httpOrigin = "{$scheme}://{$canonicalHost}{$canonicalPort}";
        $webSocketScheme = $scheme === 'https' ? 'wss' : 'ws';

        return ['http' => $httpOrigin, 'websocket' => "{$webSocketScheme}://{$canonicalHost}{$canonicalPort}"];
    }

    private function isValidHost(string $host): bool
    {
        return filter_var($host, FILTER_VALIDATE_IP) !== false
            || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }
}
