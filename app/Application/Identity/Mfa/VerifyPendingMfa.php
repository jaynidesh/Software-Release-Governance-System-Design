<?php

declare(strict_types=1);

namespace App\Application\Identity\Mfa;

use App\Contracts\Identity\AuthenticatedSessionCreator;
use App\Contracts\Identity\TotpVerifier;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Domain\Identity\Enums\UserState;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Models\UserRecoveryCode;
use App\Notifications\Identity\RecoveryCodeUsedNotification;
use App\Services\Identity\AccountLockout;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\OtpHasher;
use App\Services\Identity\PrivilegedPermissionResolver;
use App\Services\Identity\RecoveryCodeHasher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

final class VerifyPendingMfa
{
    public function __construct(
        private readonly TotpVerifier $totp,
        private readonly RecoveryCodeHasher $recoveryCodes,
        private readonly AccountLockout $lockout,
        private readonly IdentityEventRecorder $events,
        private readonly AuthenticatedSessionCreator $sessions,
        private readonly Session $session,
        private readonly OtpHasher $hasher,
        private readonly PrivilegedPermissionResolver $privilegedPermissions,
    ) {}

    /** @return array{used_recovery: bool, remaining_recovery: int} */
    public function handle(
        PendingAuthentication $pending,
        string $code,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): array {
        $result = DB::transaction(function () use ($pending, $code, $ipAddress, $userAgent, $correlationId): ?array {
            $user = User::query()->whereKey($pending->user_id)->lockForUpdate()->first();
            $lockedPending = PendingAuthentication::query()->whereKey($pending->id)->lockForUpdate()->first();
            $method = UserMfaMethod::query()
                ->where('user_id', $pending->user_id)
                ->where('type', MfaMethodType::Totp)
                ->whereNotNull('confirmed_at')
                ->whereNull('disabled_at')
                ->lockForUpdate()
                ->first();

            if ($user === null || $lockedPending === null || $method === null
                || ! $this->pendingIsCurrent($lockedPending, $user)) {
                return null;
            }

            $usedRecovery = false;
            $valid = false;

            if (preg_match('/^\d{6}$/', $code) === 1) {
                $step = $this->totp->verify($method->secret, $code);
                $valid = $step !== null
                    && ($method->last_accepted_timestep === null || $step > $method->last_accepted_timestep);

                if ($valid) {
                    $method->update(['last_accepted_timestep' => $step]);
                }
            } else {
                $recoveryRows = UserRecoveryCode::query()
                    ->where('user_mfa_method_id', $method->id)
                    ->whereNull('used_at')
                    ->lockForUpdate()
                    ->get();

                foreach ($recoveryRows as $recoveryRow) {
                    if ($this->recoveryCodes->verify($code, $method->id, $recoveryRow->code_hmac)) {
                        $recoveryRow->update(['used_at' => now()]);
                        $usedRecovery = true;
                        $valid = true;
                        break;
                    }
                }
            }

            if (! $valid) {
                $locked = $this->lockout->recordFailure($user);
                $this->events->security(
                    'identity.mfa.verification_failed',
                    null,
                    $user,
                    ['purpose' => $this->purpose($lockedPending)->value],
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                if ($locked) {
                    $this->events->security('identity.account.locked', null, $user, [], $ipAddress, $userAgent, $correlationId);
                }

                return null;
            }

            $lockedPending->update(['completed_at' => now()]);

            $purpose = $this->purpose($lockedPending);

            if ($purpose === AuthenticationPurpose::Activation) {
                $user->forceFill([
                    'state' => UserState::Active,
                    'activated_at' => now(),
                    'email_verified_at' => $user->email_verified_at ?? now(),
                ]);
            }

            $user->forceFill(['last_login_at' => now()])->save();
            $this->lockout->reset($user);
            $remaining = UserRecoveryCode::query()
                ->where('user_mfa_method_id', $method->id)
                ->whereNull('used_at')
                ->count();
            $this->events->security(
                $usedRecovery ? 'identity.recovery_code.used' : 'identity.mfa.verified',
                $user,
                $user,
                ['purpose' => $purpose->value, 'remaining_recovery_codes' => $remaining],
                $ipAddress,
                $userAgent,
                $correlationId,
            );

            if ($usedRecovery) {
                DB::afterCommit(static fn () => $user->notify(new RecoveryCodeUsedNotification));
            }

            $this->recordAuthenticationSuccess($user, $purpose, $ipAddress, $userAgent, $correlationId);
            $this->sessions->create($user, $purpose, true);

            return ['used_recovery' => $usedRecovery, 'remaining_recovery' => $remaining];
        }, 3);

        if ($result === null) {
            throw ValidationException::withMessages(['code' => 'The authentication code is invalid or expired.']);
        }

        return $result;
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

    private function recordAuthenticationSuccess(
        User $user,
        AuthenticationPurpose $purpose,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        $this->events->login(
            $user->email,
            $purpose,
            'AUTHENTICATION_SUCCEEDED',
            $user,
            $ipAddress,
            $userAgent,
            $correlationId,
        );
        $this->events->security(
            'identity.authentication.succeeded',
            $user,
            $user,
            ['purpose' => $purpose->value],
            $ipAddress,
            $userAgent,
            $correlationId,
        );
    }
}
