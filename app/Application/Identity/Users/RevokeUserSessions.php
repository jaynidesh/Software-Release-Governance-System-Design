<?php

declare(strict_types=1);

namespace App\Application\Identity\Users;

use App\Application\Identity\Sessions\RevokeAllSessions;
use App\Contracts\Identity\AuthorizationService;
use App\Models\User;
use App\Services\Identity\IdentityMutationBoundary;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class RevokeUserSessions
{
    public function __construct(private readonly IdentityMutationBoundary $mutationBoundary,
        private readonly AuthorizationService $authorization,
        private readonly RevokeAllSessions $revokeAllSessions,
    ) {}

    public function handle(
        User $actor,
        User $target,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        $this->mutationBoundary->run(function () use ($actor, $target, $ipAddress, $userAgent, $correlationId): void {
            DB::transaction(function () use (
                $actor,
                $target,
                $ipAddress,
                $userAgent,
                $correlationId,
            ): void {
                $users = User::query()
                    ->whereKey([(int) $actor->getKey(), (int) $target->getKey()])
                    ->orderBy('id')
                    ->lockForUpdate()
                    ->get()
                    ->keyBy('id');
                $lockedActor = $users->get($actor->getKey());
                $lockedTarget = $users->get($target->getKey());

                if (! $lockedActor instanceof User || ! $lockedTarget instanceof User
                    || ! $this->authorization->allows($lockedActor, 'admin.users', null, true)) {
                    throw new AuthorizationException;
                }

                $this->revokeAllSessions->handle(
                    $lockedActor,
                    $lockedTarget,
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );
            }, 3);
        }, $actor, self::class, $ipAddress, $userAgent, $correlationId);
    }
}
