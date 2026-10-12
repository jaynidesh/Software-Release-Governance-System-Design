<?php

declare(strict_types=1);

namespace App\Application\Identity\Sessions;

use App\Contracts\Identity\AuthorizationService;
use App\Models\AuthSession;
use App\Models\User;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\IdentityMutationBoundary;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;

final class RevokeSession
{
    public function __construct(private readonly IdentityMutationBoundary $mutationBoundary,
        private readonly AuthorizationService $authorization,
        private readonly IdentityEventRecorder $events,
        private readonly Session $session,
    ) {}

    public function handle(
        User $actor,
        AuthSession $authSession,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): bool {
        return $this->mutationBoundary->run(function () use ($actor, $authSession, $ipAddress, $userAgent, $correlationId): bool {
            return DB::transaction(function () use ($actor, $authSession, $ipAddress, $userAgent, $correlationId): bool {
                $userIds = [(int) $actor->getKey(), (int) $authSession->user_id];
                sort($userIds);
                $users = User::query()->whereKey($userIds)->orderBy('id')->lockForUpdate()->get()->keyBy('id');
                $lockedActor = $users->get($actor->getKey());
                $target = $users->get($authSession->user_id);
                $lockedSession = AuthSession::query()
                    ->whereKey($authSession->getKey())
                    ->where('user_id', $authSession->user_id)
                    ->lockForUpdate()
                    ->firstOrFail();

                if (! $lockedActor instanceof User || ! $target instanceof User) {
                    throw new AuthorizationException;
                }

                if (! $lockedActor->is($target)
                    && ! $this->authorization->allows($lockedActor, 'admin.users', null, true)) {
                    throw new AuthorizationException;
                }

                $isCurrent = hash_equals($this->session->getId(), $lockedSession->session_id);
                $this->events->security(
                    'identity.session.revoked',
                    $lockedActor,
                    $target,
                    [],
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );
                DB::table('sessions')->where('id', $lockedSession->session_id)->delete();
                $lockedSession->delete();

                return $isCurrent;
            }, 3);
        }, $actor, self::class, $ipAddress, $userAgent, $correlationId);
    }
}
