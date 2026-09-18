<?php

declare(strict_types=1);

namespace Database\Factories;

use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/** @extends Factory<RoleAssignment> */
class RoleAssignmentFactory extends Factory
{
    /** @return array<string, mixed> */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'role_id' => Role::factory(),
            'application_id' => null,
            'starts_at' => now()->subMinute(),
            'ends_at' => null,
            'revoked_at' => null,
            'assigned_by' => null,
            'revoked_by' => null,
        ];
    }

    public function revoked(): static
    {
        return $this->state(fn (): array => ['revoked_at' => now()]);
    }
}
