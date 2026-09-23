<?php

declare(strict_types=1);

namespace App\Application\Identity\Mfa;

use App\Contracts\Identity\TotpVerifier;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Domain\Identity\Enums\UserState;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Services\Identity\AccountLockout;
use App\Services\Identity\LocalTotpQrCode;
use App\Services\Identity\OtpHasher;
use App\Services\Identity\PrivilegedPermissionResolver;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

final class BeginTotpEnrollment
{
    public function __construct(
        private readonly TotpVerifier $totp,
        private readonly LocalTotpQrCode $qrCode,
        private readonly Session $session,
        private readonly OtpHasher $hasher,
        private readonly PrivilegedPermissionResolver $privilegedPermissions,
        private readonly AccountLockout $lockout,
    ) {}

    /** @return array{method: UserMfaMethod, secret: ?string, svg: ?string} */
    public function handle(PendingAuthentication $pending): array
    {
        return DB::transaction(function () use ($pending): array {
            $user = User::query()->whereKey($pending->user_id)->lockForUpdate()->first();
            $lockedPending = PendingAuthentication::query()->whereKey($pending->id)->lockForUpdate()->first();

            if ($user === null || $lockedPending === null || ! $this->pendingIsCurrent($lockedPending, $user)) {
                throw ValidationException::withMessages(['code' => 'The authentication state is invalid or expired.']);
            }

            $method = UserMfaMethod::query()
                ->where('user_id', $pending->user_id)
                ->where('type', MfaMethodType::Totp)
                ->lockForUpdate()
                ->first();

            if ($method !== null && $method->confirmed_at === null
                && $method->created_at?->lte(now()->subMinutes((int) config('identity.totp.unconfirmed_ttl_minutes')))) {
                $method->delete();
                $method = null;
            }

            if ($method !== null) {
                return ['method' => $method, 'secret' => null, 'svg' => null];
            }

            $secret = $this->totp->generateSecret();
            $method = UserMfaMethod::query()->create([
                'user_id' => $pending->user_id,
                'type' => MfaMethodType::Totp,
                'secret' => $secret,
            ]);
            $uri = $this->totp->provisioningUri($secret, $user->email);

            return ['method' => $method, 'secret' => $secret, 'svg' => $this->qrCode->render($uri)];
        }, 3);
    }

    private function pendingIsCurrent(PendingAuthentication $pending, User $user): bool
    {
        $purpose = $this->purpose($pending);
        $state = $this->state($user);

        return $pending->completed_at === null
            && $pending->invalidated_at === null
            && now()->isBefore($pending->expires_at)
            && $pending->user_session_version === $user->session_version
            && hash_equals($pending->session_id_hmac, $this->hasher->hashSessionId($this->session->getId()))
            && ! $this->lockout->isLocked($user)
            && $this->privilegedPermissions->userIsPrivileged($user)
            && match ($purpose) {
                AuthenticationPurpose::Activation => $state === UserState::Invited
                    && $user->email_verified_at !== null
                    && $user->invitation_expires_at !== null
                    && now()->isBefore($user->invitation_expires_at),
                AuthenticationPurpose::Login, AuthenticationPurpose::Reauthentication => $state === UserState::Active,
            };
    }

    private function purpose(PendingAuthentication $pending): AuthenticationPurpose
    {
        $purpose = $pending->getAttribute('purpose');

        return $purpose instanceof AuthenticationPurpose ? $purpose : AuthenticationPurpose::from((string) $purpose);
    }

    private function state(User $user): UserState
    {
        $state = $user->getAttribute('state');

        return $state instanceof UserState ? $state : UserState::from((string) $state);
    }
}
