<?php

declare(strict_types=1);

namespace App\Application\Identity\Roles;

use App\Contracts\Identity\AuthorizationService;
use App\Models\Role;
use App\Models\User;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class UpdateRole
{
    public function __construct(
        private readonly AuthorizationService $authorization,
        private readonly EffectiveAdministratorGuard $administrators,
        private readonly IdentityEventRecorder $events,
    ) {}

    /** @param array{code?: string, name: string, description?: string|null} $attributes */
    public function handle(
        User $actor,
        Role $role,
        array $attributes,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): Role {
        return DB::transaction(function () use (
            $actor,
            $role,
            $attributes,
            $ipAddress,
            $userAgent,
            $correlationId,
        ): Role {
            $this->administrators->lockMutex();
            $lockedActor = User::query()->whereKey($actor->getKey())->lockForUpdate()->firstOrFail();

            if (! $this->authorization->allows($lockedActor, 'admin.roles', null, true)) {
                throw new AuthorizationException;
            }

            $lockedRole = Role::query()->whereKey($role->getKey())->lockForUpdate()->firstOrFail();
            $lockedRole->forceFill([
                'code' => $lockedRole->is_system
                    ? $lockedRole->code
                    : mb_strtolower(trim($attributes['code'] ?? $lockedRole->code)),
                'name' => trim($attributes['name']),
                'description' => isset($attributes['description']) ? trim($attributes['description']) : null,
            ])->save();
            $this->events->security(
                'identity.role.updated',
                $lockedActor,
                null,
                ['role_public_id' => $lockedRole->public_id],
                $ipAddress,
                $userAgent,
                $correlationId,
            );

            return $lockedRole;
        }, 3);
    }
}
