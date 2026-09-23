<?php

declare(strict_types=1);

namespace App\Application\Identity\Authentication;

use App\Models\PendingAuthentication;
use App\Models\User;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\OtpHasher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;

final class CancelPendingAuthentication
{
    public function __construct(
        private readonly Session $session,
        private readonly OtpHasher $hasher,
        private readonly IdentityEventRecorder $events,
    ) {}

    public function handle(
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        $reference = $this->session->get('identity.pending_authentication');
        $identity = is_string($reference)
            ? PendingAuthentication::query()->select(['id', 'user_id'])->where('public_id', $reference)->first()
            : null;

        if ($identity !== null) {
            DB::transaction(function () use ($identity, $ipAddress, $userAgent, $correlationId): void {
                $user = User::query()->whereKey($identity->user_id)->lockForUpdate()->first();
                $pending = PendingAuthentication::query()->whereKey($identity->getKey())->lockForUpdate()->first();

                $rejectionReason = match (true) {
                    $user === null || $pending === null => 'missing_state',
                    $pending->completed_at !== null => 'completed',
                    $pending->invalidated_at !== null => 'invalidated',
                    now()->greaterThanOrEqualTo($pending->expires_at) => 'expired',
                    $pending->user_session_version !== $user->session_version => 'session_version',
                    ! hash_equals($pending->session_id_hmac, $this->hasher->hashSessionId($this->session->getId())) => 'session_binding',
                    default => null,
                };

                if ($rejectionReason !== null) {
                    $this->events->security(
                        'identity.authentication.pending_cancel_rejected',
                        null,
                        $user,
                        ['reason' => $rejectionReason],
                        $ipAddress,
                        $userAgent,
                        $correlationId,
                    );

                    return;
                }

                $pending->update(['invalidated_at' => now()]);
                $this->events->security(
                    'identity.authentication.pending_cancelled',
                    null,
                    $user,
                    ['pending_reference' => $pending->public_id],
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );
            }, 3);
        }

        $this->session->invalidate();
        $this->session->regenerateToken();
    }
}
