<?php

declare(strict_types=1);

namespace App\Application\Identity\Mfa;

use App\Contracts\Identity\TotpVerifier;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Models\AuthSession;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\LocalTotpQrCode;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;

final class RotateTotp
{
    public function __construct(
        private readonly Session $session,
        private readonly TotpVerifier $totp,
        private readonly LocalTotpQrCode $qrCode,
        private readonly IdentityEventRecorder $events,
    ) {}

    /** @return array{secret: string, svg: string} */
    public function handle(User $user, ?string $ipAddress, ?string $userAgent, ?string $correlationId): array
    {
        return DB::transaction(function () use ($user, $ipAddress, $userAgent, $correlationId): array {
            $lockedUser = User::query()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $this->assertFreshMfa($lockedUser);
            $method = UserMfaMethod::query()
                ->where('user_id', $lockedUser->id)
                ->where('type', MfaMethodType::Totp)
                ->whereNotNull('confirmed_at')
                ->whereNull('disabled_at')
                ->lockForUpdate()
                ->firstOrFail();
            $secret = $this->totp->generateSecret();
            $method->recoveryCodes()->delete();
            $method->forceFill([
                'secret' => $secret,
                'confirmed_at' => null,
                'rotated_at' => now(),
                'last_accepted_timestep' => null,
            ])->save();
            $lockedUser->increment('session_version');
            $this->events->security(
                'identity.mfa.rotated',
                $lockedUser,
                $lockedUser,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $uri = $this->totp->provisioningUri($secret, $lockedUser->email);

            return ['secret' => $secret, 'svg' => $this->qrCode->render($uri)];
        }, 3);
    }

    private function assertFreshMfa(User $user): void
    {
        $fresh = AuthSession::query()
            ->where('session_id', $this->session->getId())
            ->where('user_id', $user->id)
            ->where('user_session_version', $user->session_version)
            ->whereNull('revoked_at')
            ->whereNotNull('mfa_authenticated_at')
            ->where('reauthenticated_at', '>=', now()->subMinutes((int) config('identity.privileged_reauth_minutes')))
            ->exists();

        if (! $fresh) {
            throw new DomainRuleViolation('fresh_mfa_required', ['Fresh email and MFA authentication is required.']);
        }
    }
}
