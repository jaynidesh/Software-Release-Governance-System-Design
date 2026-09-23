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
        if ($actor->is($target)) {
            throw new DomainRuleViolation('self_mfa_reset', ['A different administrator must reset multi-factor authentication.']);
        }

        if (! $this->authorization->allows($actor, 'admin.users', null, true)) {
            throw new DomainRuleViolation('unauthorized_mfa_reset', ['Fresh administrator authentication is required.']);
        }

        DB::transaction(function () use ($actor, $target, $ipAddress, $userAgent, $correlationId): void {
            $lockedTarget = User::query()->whereKey($target->id)->lockForUpdate()->firstOrFail();
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
                $actor,
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
