<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Domain\Identity\Enums\UserState;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use Database\Seeders\IdentityAuthorizationSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

final class BootstrapAdministratorCommandTest extends TestCase
{
    use RefreshDatabase;

    public function test_command_is_interactive_only_and_has_no_credential_options(): void
    {
        $this->artisan('identity:bootstrap-admin', ['--no-interaction' => true])
            ->expectsOutputToContain('interactive')
            ->assertFailed();

        $definition = Artisan::all()['identity:bootstrap-admin']->getDefinition();
        self::assertFalse($definition->hasOption('email'));
        self::assertFalse($definition->hasOption('password'));
        self::assertFalse($definition->hasOption('otp'));
    }

    public function test_first_bootstrap_creates_one_invited_nonexpiring_global_administrator_and_second_refuses(): void
    {
        Notification::fake();
        $this->seed(IdentityAuthorizationSeeder::class);

        $this->artisan('identity:bootstrap-admin')
            ->expectsQuestion('Employee number (optional)', ' E-001 ')
            ->expectsQuestion('Name', ' Initial Administrator ')
            ->expectsQuestion('Email', ' ADMIN@EXAMPLE.TEST ')
            ->expectsQuestion('Timezone', 'Indian/Mauritius')
            ->assertSuccessful();

        $user = User::query()->sole();
        self::assertSame(UserState::Invited, $user->state);
        self::assertSame('admin@example.test', $user->email);
        $assignment = RoleAssignment::query()->sole();
        self::assertNull($assignment->application_id);
        self::assertNull($assignment->ends_at);
        self::assertLessThanOrEqual(now(), $assignment->starts_at);
        Notification::assertSentTo($user, ActivationInvitationNotification::class);
        $this->assertDatabaseHas('security_events', ['event_code' => 'identity.administrator.bootstrapped']);

        $this->artisan('identity:bootstrap-admin')
            ->expectsQuestion('Employee number (optional)', '')
            ->expectsQuestion('Name', 'Another')
            ->expectsQuestion('Email', 'another@example.test')
            ->expectsQuestion('Timezone', 'UTC')
            ->expectsOutputToContain('already exists')
            ->assertFailed();
        self::assertSame(1, User::query()->count());
    }
}
