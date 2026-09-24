<?php

declare(strict_types=1);

namespace App\Application\Identity\Sessions;

use App\Contracts\Identity\AuthorizationService;
use App\Models\AuthSession;
use App\Models\User;
use App\Services\Identity\IdentityEventRecorder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class RevokeAllSessions
{
    public function __construct(
        private readonly AuthorizationService $authorization,
        private readonly IdentityEventRecorder $events,
    ) {}

    public function handle(
        User $actor,
        User $target,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        DB::transaction(function () use ($actor, $target, $ipAddress, $userAgent, $correlationId): void {
            $userIds = [(int) $actor->getKey(), (int) $target->getKey()];
            sort($userIds);
            $users = User::query()->whereKey($userIds)->orderBy('id')->lockForUpdate()->get()->keyBy('id');
            $lockedActor = $users->get($actor->getKey());
            $lockedTarget = $users->get($target->getKey());

            if (! $lockedActor instanceof User || ! $lockedTarget instanceof User) {
                throw new AuthorizationException;
            }

            if (! $lockedActor->is($lockedTarget)
                && ! $this->authorization->allows($lockedActor, 'admin.users', null, true)) {
                throw new AuthorizationException;
            }

            $sessionIds = AuthSession::query()
                ->where('user_id', $lockedTarget->getKey())
                ->lockForUpdate()
                ->pluck('session_id');
            $lockedTarget->increment('session_version');
            $this->events->security(
                'identity.sessions.revoked_all',
                $lockedActor,
                $lockedTarget,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            DB::table('sessions')->whereIn('id', $sessionIds)->delete();
            AuthSession::query()->where('user_id', $lockedTarget->getKey())->delete();
        }, 3);
    }
}
