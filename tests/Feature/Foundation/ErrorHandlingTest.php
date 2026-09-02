<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

final class ErrorHandlingTest extends TestCase
{
    public function test_every_response_has_a_server_generated_correlation_id(): void
    {
        $response = $this->withHeader('X-Correlation-ID', 'untrusted')->getJson('/health')->assertOk();
        $id = (string) $response->headers->get('X-Correlation-ID');

        self::assertNotSame('untrusted', $id);
        self::assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $id);
    }

    public function test_domain_failures_are_structured_without_internal_details(): void
    {
        Route::get('/_test/domain-error', static function (): never {
            throw new DomainRuleViolation('mandatory_checklist_incomplete', ['Complete DEV-01.']);
        });

        $response = $this->getJson('/_test/domain-error')
            ->assertStatus(409)
            ->assertJsonPath('code', 'mandatory_checklist_incomplete')
            ->assertJsonPath('failures.0', 'Complete DEV-01.')
            ->assertJsonMissing(['trace', 'file', 'line']);

        self::assertMatchesRegularExpression(
            '/^[0-9a-f-]{36}$/',
            (string) $response->headers->get('X-Correlation-ID'),
        );
        self::assertSame(
            $response->headers->get('X-Correlation-ID'),
            $response->json('correlation_id'),
        );
    }

    public function test_other_rendered_exceptions_have_a_correlation_id(): void
    {
        Route::get('/_test/unexpected-error', static function (): never {
            throw new \RuntimeException('private detail');
        });

        $response = $this->getJson('/_test/unexpected-error')->assertStatus(500);

        self::assertMatchesRegularExpression(
            '/^[0-9a-f-]{36}$/',
            (string) $response->headers->get('X-Correlation-ID'),
        );
    }
}
