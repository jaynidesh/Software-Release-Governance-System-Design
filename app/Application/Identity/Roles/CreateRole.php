<?php

declare(strict_types=1);

namespace App\Application\Identity\Roles;

use App\Contracts\Identity\AuthorizationService;
use App\Models\Role;
use App\Models\User;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\IdentityMutationBoundary;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class CreateRole
{
    public function __construct(private readonly IdentityMutationBoundary $mutationBoundary,
        private readonly AuthorizationService $authorization,
        private readonly EffectiveAdministratorGuard $administrators,
        private readonly IdentityEventRecorder $events,
    ) {}

    /** @param array{code: string, name: string, description?: string|null} $attributes */
    public function handle(
        User $actor,
        array $attributes,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): Role {
        return $this->mutationBoundary->run(function () use ($actor, $attributes, $ipAddress, $userAgent, $correlationId): Role {
            return DB::transaction(function () use (
                $actor,
                $attributes,
                $ipAddress,
                $userAgent,
                $correlationId,
            ): Role {
                $this->administrators->lockMutex();
                $lockedActor = User::query()->whereKey($actor->getKey())->lockForUpdate()->firstOrFail();
                $this->authorize($lockedActor);
                $role = Role::query()->create([
                    'code' => mb_strtolower(trim($attributes['code'])),
                    'name' => trim($attributes['name']),
                    'description' => isset($attributes['description']) ? trim($attributes['description']) : null,
                    'is_system' => false,
                    'is_active' => true,
                ]);
                $this->events->security(
                    'identity.role.created',
                    $lockedActor,
                    null,
                    ['role_public_id' => $role->public_id],
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                return $role;
            }, 3);
        }, $actor, self::class, $ipAddress, $userAgent, $correlationId);
    }

    private function authorize(User $actor): void
    {
        if (! $this->authorization->allows($actor, 'admin.roles', null, true)) {
            throw new AuthorizationException;
        }
    }
}
