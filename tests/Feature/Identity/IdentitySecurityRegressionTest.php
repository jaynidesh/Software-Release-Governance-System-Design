<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Application\Identity\Assignments\AssignRole;
use App\Application\Identity\Users\ChangeUserState;
use App\Application\Identity\Users\CreateInvitedUser;
use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\Application;
use App\Models\AuthSession;
use App\Models\LoginEvent;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Services\Identity\EloquentAuthorizationService;
use App\Support\Exceptions\DomainRuleViolation;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class IdentitySecurityRegressionTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->seed(IdentityAuthorizationSeeder::class);
    }

    public function test_enumeration_resistance_and_event_correlation_share_the_real_http_boundary(): void
    {
        User::factory()->suspended()->create(['email' => 'known@example.test']);

        $unknown = $this->post('/login/otp', ['email' => 'unknown@example.test']);
        $known = $this->post('/login/otp', ['email' => 'known@example.test']);

        self::assertSame($unknown->getStatusCode(), $known->getStatusCode());
        self::assertSame($unknown->headers->get('Location'), $known->headers->get('Location'));
        $unknown->assertSessionHas('status', 'If the account is eligible, a sign-in code will be sent.');
        $known->assertSessionHas('status', 'If the account is eligible, a sign-in code will be sent.');
        foreach ([$unknown, $known] as $response) {
            $correlationId = $response->headers->get('X-Correlation-ID');
            self::assertIsString($correlationId);
            self::assertTrue(LoginEvent::query()->where('correlation_id', $correlationId)->exists());
        }
    }

    public function test_application_scope_isolation_is_enforced_by_the_real_authorization_service(): void
    {
        $user = User::factory()->active()->create();
        $first = Application::factory()->create();
        $second = Application::factory()->create();
        $role = Role::factory()->create();
        $permission = Permission::query()->where('code', 'release.view')->firstOrFail();
        $role->permissions()->attach($permission);
        RoleAssignment::factory()->create([
            'user_id' => $user->id,
            'role_id' => $role->id,
            'application_id' => $first->id,
        ]);
        $this->authenticate($user);

        $authorization = $this->app->make(EloquentAuthorizationService::class);

        self::assertTrue($authorization->allows($user, 'release.view', $first, false));
        self::assertFalse($authorization->allows($user, 'release.view', $second, false));
        self::assertFalse($authorization->allows($user, 'release.view', null, false));
    }

    public function test_self_escalation_and_final_administrator_loss_are_rejected_and_correlated(): void
    {
        $actor = User::factory()->active()->create();
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();
        RoleAssignment::factory()->create([
            'user_id' => $actor->id,
            'role_id' => $administrator->id,
        ]);
        $this->app->bind(AuthorizationService::class, fn () => $this->allowAdministration());

        try {
            $this->app->make(AssignRole::class)->handle(
                $actor,
                $actor,
                Role::factory()->create(),
                null,
                now(),
                null,
                null,
                null,
                'corr-self',
            );
            self::fail('Self-escalation was accepted.');
        } catch (DomainRuleViolation $exception) {
            self::assertSame('self_role_assignment', $exception->ruleCode);
        }

        try {
            $this->app->make(ChangeUserState::class)->handle(
                $actor,
                $actor,
                UserState::Deactivated,
                null,
                null,
                'corr-final',
            );
            self::fail('The final effective administrator was removed.');
        } catch (DomainRuleViolation $exception) {
            self::assertSame('last_effective_administrator', $exception->ruleCode);
        }

        self::assertSame(UserState::Active, $actor->refresh()->state);
        self::assertTrue(SecurityEvent::query()
            ->where('event_code', 'identity.administrator.last_protected')
            ->where('correlation_id', 'corr-final')
            ->exists());
    }

    public function test_invitation_notification_is_encrypted_after_commit_and_contains_no_bearer_secret(): void
    {
        $actor = User::factory()->active()->create();
        $this->app->bind(AuthorizationService::class, fn () => $this->allowAdministration());

        DB::beginTransaction();
        $user = $this->app->make(CreateInvitedUser::class)->handle($actor, [
            'employee_number' => null,
            'name' => 'Invited Person',
            'email' => 'invited@example.test',
            'timezone' => 'UTC',
        ], null, null, 'corr-invite');
        self::assertSame(0, DB::table('jobs')->count());
        DB::commit();

        /** @var array{data: array{command: string}} $payload */
        $payload = json_decode((string) DB::table('jobs')->sole()->payload, true, flags: JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString('invited@example.test', json_encode($payload, JSON_THROW_ON_ERROR));
        $serialized = $this->app->make(Encrypter::class)->decrypt($payload['data']['command']);
        self::assertIsString($serialized);
        $job = unserialize($serialized, ['allowed_classes' => true]);
        self::assertInstanceOf(SendQueuedNotifications::class, $job);
        self::assertTrue($job->shouldBeEncrypted);
        self::assertInstanceOf(ActivationInvitationNotification::class, $job->notification);
        self::assertTrue($job->notification->afterCommit);
        $mail = $job->notification->toMail($user)->toArray();
        self::assertStringNotContainsString('token', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
        self::assertStringNotContainsString('code', mb_strtolower(json_encode($mail, JSON_THROW_ON_ERROR)));
    }

    private function authenticate(User $user): void
    {
        $sessionId = str_pad((string) $user->id, 40, '0', STR_PAD_LEFT);
        $session = $this->app->make(Session::class);
        $session->setId($sessionId);
        $this->withCookie((string) config('session.cookie'), $sessionId);
        AuthSession::query()->create([
            'session_id' => $sessionId,
            'user_id' => $user->id,
            'started_at' => now(),
            'last_seen_at' => now(),
            'absolute_expires_at' => now()->addHour(),
            'primary_authenticated_at' => now(),
            'user_session_version' => $user->session_version,
        ]);
    }

    private function allowAdministration(): AuthorizationService
    {
        return new class implements AuthorizationService
        {
            public function allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool
            {
                return $requiresFreshReauthentication && in_array($permission, ['admin.users', 'admin.roles'], true);
            }
        };
    }
}
