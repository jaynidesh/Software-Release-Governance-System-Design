<?php

declare(strict_types=1);

namespace App\Application\Identity\Mfa;

use App\Contracts\Identity\AuthorizationService;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Notifications\Identity\MfaResetNotification;
use App\Services\Identity\IdentityEventRecorder;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Support\Facades\DB;

final class ResetUserMfa
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
            $ids = [(int) $actor->getKey(), (int) $target->getKey()];
            sort($ids);
            $lockedUsers = User::query()
                ->whereKey($ids)
                ->orderBy('id')
                ->lockForUpdate()
                ->get()
                ->keyBy('id');
            $lockedActor = $lockedUsers->get($actor->getKey());
            $lockedTarget = $lockedUsers->get($target->getKey());

            if (! $lockedActor instanceof User || ! $lockedTarget instanceof User) {
                throw new DomainRuleViolation('invalid_mfa_reset_target', ['The multi-factor reset target is unavailable.']);
            }

            if ($lockedActor->is($lockedTarget)) {
                throw new DomainRuleViolation('self_mfa_reset', ['A different administrator must reset multi-factor authentication.']);
            }

            if (! $this->authorization->allows($lockedActor, 'admin.users', null, true)) {
                throw new DomainRuleViolation('unauthorized_mfa_reset', ['Fresh administrator authentication is required.']);
            }

            $methods = UserMfaMethod::query()->where('user_id', $lockedTarget->id)->lockForUpdate()->get();

            foreach ($methods as $method) {
                $method->recoveryCodes()->delete();
                $method->update(['disabled_at' => now()]);
            }

            AuthChallenge::query()
                ->where('user_id', $lockedTarget->id)
                ->whereNull('consumed_at')
                ->whereNull('invalidated_at')
                ->update(['invalidated_at' => now()]);
            PendingAuthentication::query()
                ->where('user_id', $lockedTarget->id)
                ->whereNull('completed_at')
                ->whereNull('invalidated_at')
                ->update(['invalidated_at' => now()]);

            $sessionIds = AuthSession::query()->where('user_id', $lockedTarget->id)->pluck('session_id');
            DB::table('sessions')->whereIn('id', $sessionIds)->delete();
            AuthSession::query()->where('user_id', $lockedTarget->id)->delete();
            $lockedTarget->increment('session_version');
            $this->events->security(
                'identity.mfa.reset',
                $lockedActor,
                $lockedTarget,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            DB::afterCommit(static fn () => $lockedTarget->notify(new MfaResetNotification));
        }, 3);
    }
}
