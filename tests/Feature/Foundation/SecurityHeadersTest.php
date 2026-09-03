<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use App\Http\Middleware\SecurityHeaders;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

final class SecurityHeadersTest extends TestCase
{
    public function test_responses_include_the_security_baseline(): void
    {
        $this->get('/health')
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
            ->assertHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            ->assertHeader('Content-Security-Policy', config('security.content_security_policy'));
    }

    public function test_hsts_is_only_sent_for_secure_production_requests(): void
    {
        app()->instance('env', 'production');

        $insecureResponse = (new SecurityHeaders)->handle(
            Request::create('/health'),
            static fn (): Response => new Response,
        );
        $secureResponse = (new SecurityHeaders)->handle(
            Request::create('/health', server: ['HTTPS' => 'on']),
            static fn (): Response => new Response,
        );

        self::assertFalse($insecureResponse->headers->has('Strict-Transport-Security'));
        self::assertSame(config('security.hsts'), $secureResponse->headers->get('Strict-Transport-Security'));
    }

    public function test_production_and_testing_keep_the_strict_content_security_policy(): void
    {
        foreach (['production', 'testing'] as $environment) {
            app()->instance('env', $environment);

            $response = (new SecurityHeaders)->handle(
                Request::create('/health'),
                static fn (): Response => new Response,
            );

            self::assertSame(config('security.content_security_policy'), $response->headers->get('Content-Security-Policy'));
            self::assertStringNotContainsString('localhost:5173', (string) $response->headers->get('Content-Security-Policy'));
            self::assertStringNotContainsString("'unsafe-inline'", (string) $response->headers->get('Content-Security-Policy'));
        }
    }

    public function test_local_development_allows_only_the_configured_vite_origin_for_hmr(): void
    {
        config()->set('security.vite_dev_server_origin', 'http://vite.test:5173');
        app()->instance('env', 'local');

        $response = (new SecurityHeaders)->handle(
            Request::create('/'),
            static fn (): Response => new Response,
        );

        self::assertSame(
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline' http://vite.test:5173; script-src 'self' http://vite.test:5173; connect-src 'self' http://vite.test:5173 ws://vite.test:5173",
            $response->headers->get('Content-Security-Policy'),
        );
    }
}
