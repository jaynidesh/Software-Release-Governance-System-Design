<?php

declare(strict_types=1);

namespace Database\Factories;

use App\Domain\Identity\Enums\MfaMethodType;
use App\Domain\Identity\Enums\PermissionScope;
use App\Domain\Identity\Enums\UserState;
use App\Models\Permission;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Models\UserMfaMethod;
use Illuminate\Database\Eloquent\Factories\Factory;

/** @extends Factory<User> */
class UserFactory extends Factory
{
    /** @return array<string, mixed> */
    public function definition(): array
    {
        return [
            'employee_number' => null,
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'state' => UserState::Active,
            'timezone' => 'UTC',
            'email_verified_at' => now(),
            'activated_at' => now(),
            'failed_auth_attempts' => 0,
            'session_version' => 1,
        ];
    }

    public function invited(): static
    {
        return $this->state(fn (): array => [
            'state' => UserState::Invited,
            'email_verified_at' => null,
            'invited_at' => now(),
            'invitation_expires_at' => now()->addDays((int) config('identity.invitation_ttl_days')),
            'activated_at' => null,
        ]);
    }

    public function active(): static
    {
        return $this->state(fn (): array => [
            'state' => UserState::Active,
            'email_verified_at' => now(),
            'activated_at' => now(),
        ]);
    }

    public function suspended(): static
    {
        return $this->active()->state(fn (): array => ['state' => UserState::Suspended]);
    }

    public function deactivated(): static
    {
        return $this->state(fn (): array => ['state' => UserState::Deactivated]);
    }

    public function locked(): static
    {
        return $this->active()->state(fn (): array => [
            'failed_auth_attempts' => (int) config('identity.lockout.attempts'),
            'failed_auth_window_started_at' => now(),
            'locked_until' => now()->addMinutes((int) config('identity.lockout.minutes')),
        ]);
    }

    public function privileged(): static
    {
        return $this->active()->afterCreating(function (User $user): void {
            $role = Role::query()->updateOrCreate(
                ['code' => 'administrator'],
                [
                    'name' => 'Administrator',
                    'description' => 'System role for Administrator responsibilities.',
                    'is_system' => true,
                    'is_active' => true,
                ],
            );
            $permission = Permission::query()->updateOrCreate(
                ['code' => 'admin.users'],
                ['description' => 'Admin Users.', 'scope_type' => PermissionScope::Global],
            );

            $role->permissions()->syncWithoutDetaching([$permission->getKey()]);

            RoleAssignment::query()->firstOrCreate([
                'user_id' => $user->id,
                'role_id' => $role->id,
                'application_id' => null,
            ], ['starts_at' => now()]);
        });
    }

    public function mfaConfirmed(): static
    {
        return $this->afterCreating(function (User $user): void {
            UserMfaMethod::query()->firstOrCreate([
                'user_id' => $user->id,
                'type' => MfaMethodType::Totp,
            ], [
                'secret' => 'TESTONLYSHAREDSECRET',
                'confirmed_at' => now(),
            ]);
        });
    }

    public function unverified(): static
    {
        return $this->state(fn (): array => ['email_verified_at' => null]);
    }
}
