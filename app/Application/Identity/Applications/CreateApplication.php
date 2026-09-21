<?php

declare(strict_types=1);

namespace App\Application\Identity\Applications;

use App\Contracts\Identity\AuthorizationService;
use App\Models\Application;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class CreateApplication
{
    public function __construct(private readonly AuthorizationService $authorization) {}

    /** @param array{code: string, name: string} $attributes */
    public function handle(User $actor, array $attributes): Application
    {
        return DB::transaction(function () use ($actor, $attributes): Application {
            $this->authorize($actor);

            return Application::query()->create([
                'code' => $attributes['code'],
                'name' => $attributes['name'],
                'is_active' => true,
            ]);
        });
    }

    private function authorize(User $actor): void
    {
        if (! $this->authorization->allows($actor, 'admin.applications', null, true)) {
            throw new AuthorizationException;
        }
    }
}
