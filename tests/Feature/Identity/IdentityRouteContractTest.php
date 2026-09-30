<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Models\Application;
use App\Models\AuthSession;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Foundation\Application as ApplicationContract;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Route as LaravelRoute;
use Tests\TestCase;

final class IdentityRouteContractTest extends TestCase
{
    use RefreshDatabase;

    public function test_identity_mutations_expose_only_the_approved_http_methods(): void
    {
        $contracts = [
            'identity.auth.otp.store' => ['POST'],
            'identity.auth.otp.verify' => ['POST'],
            'identity.auth.otp.resend' => ['POST'],
            'identity.auth.pending.cancel' => ['POST'],
            'logout' => ['POST'],
            'admin.users.state.update' => ['PATCH'],
            'admin.users.invitations.store' => ['POST'],
            'admin.users.invitations.destroy' => ['DELETE'],
            'admin.users.role-assignments.store' => ['POST'],
            'admin.users.role-assignments.destroy' => ['DELETE'],
            'identity.sessions.destroy' => ['DELETE'],
            'identity.sessions.destroy-all' => ['DELETE'],
        ];

        foreach ($contracts as $name => $methods) {
            $route = app('router')->getRoutes()->getByName($name);
            self::assertInstanceOf(LaravelRoute::class, $route, $name);
            self::assertSame($methods, array_values(array_diff($route->methods(), ['HEAD'])), $name);
        }
    }

    public function test_route_generation_discloses_public_ulids_instead_of_internal_keys(): void
    {
        $user = User::factory()->active()->create();
        $role = Role::factory()->create();
        $application = Application::factory()->create();
        $assignment = RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => $application->id,
        ]);
        $authSession = AuthSession::query()->create([
            'session_id' => str_repeat('s', 40),
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'user_session_version' => $user->session_version,
        ]);

        $urls = [
            route('admin.users.show', $user),
            route('admin.roles.show', $role),
            route('admin.applications.edit', $application),
            route('admin.users.role-assignments.destroy', [$user, $assignment]),
            route('identity.sessions.destroy', $authSession),
        ];

        foreach ($urls as $url) {
            self::assertStringNotContainsString('/'.$user->id, $url);
            self::assertStringNotContainsString('/'.$role->id, $url);
            self::assertStringNotContainsString('/'.$application->id, $url);
            self::assertStringNotContainsString('/'.$assignment->id, $url);
            self::assertStringNotContainsString('/'.$authSession->id, $url);
            self::assertStringNotContainsString($authSession->session_id, $url);
        }
    }

    public function test_authentication_responses_are_not_cacheable_and_resend_requires_csrf(): void
    {
        $this->withoutVite();

        $this->get('/login')->assertOk()->assertHeader('Cache-Control', 'no-store, private');
        $this->get('/login/verify')->assertOk()->assertHeader('Cache-Control', 'no-store, private');

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

        $this->post('/login/resend')->assertStatus(419);
    }
}
