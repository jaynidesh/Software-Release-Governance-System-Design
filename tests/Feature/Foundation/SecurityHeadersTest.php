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
}
