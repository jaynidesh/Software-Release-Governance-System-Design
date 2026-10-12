<?php

declare(strict_types=1);

namespace App\Application\Identity\Applications;

use App\Contracts\Identity\AuthorizationService;
use App\Models\Application;
use App\Models\User;
use App\Services\Identity\IdentityMutationBoundary;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class UpdateApplication
{
    public function __construct(private readonly IdentityMutationBoundary $mutationBoundary, private readonly AuthorizationService $authorization) {}

    /** @param array{name: string} $attributes */
    public function handle(User $actor, Application $application, array $attributes): Application
    {
        return $this->mutationBoundary->run(function () use ($actor, $application, $attributes): Application {
            return DB::transaction(function () use ($actor, $application, $attributes): Application {
                $this->authorize($actor);

                $lockedApplication = Application::query()
                    ->whereKey($application->getKey())
                    ->lockForUpdate()
                    ->firstOrFail();
                $lockedApplication->update(['name' => $attributes['name']]);

                return $lockedApplication;
            });
        }, $actor, self::class, null, null, null);
    }

    private function authorize(User $actor): void
    {
        if (! $this->authorization->allows($actor, 'admin.applications', null, true)) {
            throw new AuthorizationException;
        }
    }
}
