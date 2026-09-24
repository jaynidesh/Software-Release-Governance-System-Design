<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Models\AuthSession;
use App\Models\User;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Foundation\Application as ApplicationContract;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class LogoutSecurityTest extends TestCase
{
    use RefreshDatabase;

    public function test_authenticated_post_logout_destroys_metadata_and_payload_and_rotates_csrf(): void
    {
        $user = User::factory()->active()->create();
        $authSession = $this->authenticate($user);
        $oldToken = $this->sessionStore()->token();

        $this->post('/logout')->assertRedirect('/login');

        $this->assertGuest();
        self::assertNotSame($oldToken, $this->sessionStore()->token());
        self::assertFalse(AuthSession::query()->whereKey($authSession->id)->exists());
        self::assertFalse(DB::table('sessions')->where('id', $authSession->session_id)->exists());
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.session.logged_out']);
    }

    #[DataProvider('unsupportedMethods')]
    public function test_logout_rejects_every_non_post_method(string $method): void
    {
        $this->call($method, '/logout')->assertMethodNotAllowed();
    }

    /** @return array<string, array{string}> */
    public static function unsupportedMethods(): array
    {
        return [
            'GET' => ['GET'],
            'PUT' => ['PUT'],
            'PATCH' => ['PATCH'],
            'DELETE' => ['DELETE'],
        ];
    }

    public function test_logout_options_is_non_mutating_and_advertises_only_post(): void
    {
        $this->options('/logout')->assertOk()->assertHeader('Allow', 'POST');
    }

    public function test_anonymous_logout_is_denied(): void
    {
        $this->post('/logout')->assertRedirect('/');
    }

    public function test_logout_without_csrf_token_is_rejected_without_mutation(): void
    {
        $this->app->bind(
            PreventRequestForgery::class,
            static fn (ApplicationContract $app): PreventRequestForgery => new class($app, $app->make(Encrypter::class)) extends PreventRequestForgery
            {
                protected function runningUnitTests(): bool
                {
                    return false;
                }
            },
        );
        $user = User::factory()->active()->create();
        $authSession = $this->authenticate($user);

        $this->post('/logout')->assertStatus(419);

        self::assertTrue(AuthSession::query()->whereKey($authSession->id)->exists());
    }

    private function authenticate(User $user): AuthSession
    {
        $session = $this->sessionStore();
        $session->start();
        $session->setId(bin2hex(random_bytes(20)));
        $this->actingAs($user);
        $this->withCookie((string) config('session.cookie'), $session->getId());

        return AuthSession::query()->create([
            'session_id' => $session->getId(),
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHours(8),
            'primary_authenticated_at' => now(),
            'user_session_version' => $user->session_version,
        ]);
    }

    private function sessionStore(): Session
    {
        return $this->app->make(Session::class);
    }
}
