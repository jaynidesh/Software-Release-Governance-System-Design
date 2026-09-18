<?php

declare(strict_types=1);

namespace Database\Factories;

use App\Domain\Identity\Enums\PermissionScope;
use App\Models\Permission;
use Illuminate\Database\Eloquent\Factories\Factory;

/** @extends Factory<Permission> */
class PermissionFactory extends Factory
{
    /** @return array<string, mixed> */
    public function definition(): array
    {
        return [
            'code' => fake()->unique()->word().'.'.fake()->word(),
            'description' => fake()->sentence(),
            'scope_type' => PermissionScope::Application,
        ];
    }
}
