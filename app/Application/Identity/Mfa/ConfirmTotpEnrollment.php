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
use App\Services\Identity\AccountLockout;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\OtpHasher;
use App\Services\Identity\PrivilegedPermissionResolver;
use App\Services\Identity\RecoveryCodeHasher;
use App\Services\Identity\TotpEnrollmentState;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

final class ConfirmTotpEnrollment
{
    private const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    public function __construct(
        private readonly TotpVerifier $totp,
        private readonly RecoveryCodeHasher $recoveryCodes,
        private readonly AuthenticatedSessionCreator $sessions,
        private readonly AccountLockout $lockout,
        private readonly IdentityEventRecorder $events,
        private readonly Session $session,
        private readonly OtpHasher $hasher,
        private readonly PrivilegedPermissionResolver $privilegedPermissions,
        private readonly TotpEnrollmentState $enrollmentState,
    ) {}

    /** @return list<string> */
    public function confirm(PendingAuthentication $pending, string $code): array
    {
        $codes = DB::transaction(function () use ($pending, $code): ?array {
            $user = User::query()->whereKey($pending->user_id)->lockForUpdate()->first();
            $lockedPending = PendingAuthentication::query()->whereKey($pending->id)->lockForUpdate()->first();
            $method = UserMfaMethod::query()
                ->where('user_id', $pending->user_id)
                ->where('type', MfaMethodType::Totp)
                ->whereNull('confirmed_at')
                ->whereNull('disabled_at')
                ->lockForUpdate()
                ->first();

            if ($user === null || $lockedPending === null || $method === null
                || ! $this->pendingIsCurrent($lockedPending, $user)
                || $this->enrollmentState->isExpired($method)
                || $method->recoveryCodes()->exists()) {
                if ($method !== null && $this->enrollmentState->isExpired($method)) {
                    $method->delete();
                }

                return null;
            }

            $step = $this->totp->verify($method->secret, $code);

            if ($step === null || ($method->last_accepted_timestep !== null && $step <= $method->last_accepted_timestep)) {
                $locked = $this->lockout->recordFailure($user);
                $this->events->security(
                    'identity.mfa.enrollment_verification_failed',
                    null,
                    $user,
                    ['purpose' => $this->purpose($lockedPending)->value],
                    null,
                    null,
                    $lockedPending->correlation_id,
                );

                if ($locked) {
                    $this->events->security('identity.account.locked', null, $user, [], null, null, $lockedPending->correlation_id);
                }

                $this->events->security(
                    'identity.authentication.failed',
                    null,
                    $user,
                    ['purpose' => $this->purpose($lockedPending)->value],
                    null,
                    null,
                    $lockedPending->correlation_id,
                );

                return null;
            }

            $method->update(['last_accepted_timestep' => $step]);
            $codes = [];

            for ($index = 0; $index < (int) config('identity.totp.recovery_code_count'); $index++) {
                $plain = $this->generateRecoveryCode((int) config('identity.totp.recovery_code_length'));
                UserRecoveryCode::query()->create([
                    'user_mfa_method_id' => $method->id,
                    'code_hmac' => $this->recoveryCodes->hash($plain, $method->id),
                ]);
                $codes[] = $plain;
            }

            return $codes;
        }, 3);

        if ($codes === null) {
            $this->reject();
        }

        return $codes;
    }

    public function acknowledge(
        PendingAuthentication $pending,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        $acknowledged = DB::transaction(function () use ($pending, $ipAddress, $userAgent, $correlationId): bool {
            $user = User::query()->whereKey($pending->user_id)->lockForUpdate()->firstOrFail();
            $lockedPending = PendingAuthentication::query()->whereKey($pending->id)->lockForUpdate()->firstOrFail();
            $method = UserMfaMethod::query()
                ->where('user_id', $user->id)
                ->where('type', MfaMethodType::Totp)
                ->whereNull('confirmed_at')
                ->whereNull('disabled_at')
                ->lockForUpdate()
                ->firstOrFail();

            if ($this->enrollmentState->isExpired($method)) {
                $method->delete();

                return false;
            }

            if (! $this->pendingIsCurrent($lockedPending, $user)
                || ! $method->recoveryCodes()->exists()) {
                return false;
            }

            $method->update(['confirmed_at' => now()]);
            $lockedPending->update(['completed_at' => now()]);

            $purpose = $this->purpose($lockedPending);

            if ($purpose === AuthenticationPurpose::Activation) {
                $user->forceFill([
                    'state' => UserState::Active,
                    'activated_at' => now(),
                    'email_verified_at' => $user->email_verified_at ?? now(),
                ]);
                $this->events->security('identity.invitation.activated', $user, $user, [], $ipAddress, $userAgent, $correlationId);
            }

            $user->forceFill(['last_login_at' => now()])->save();
            $this->lockout->reset($user);
            $this->events->security('identity.mfa.enrolled', $user, $user, [], $ipAddress, $userAgent, $correlationId);
            $this->recordAuthenticationSuccess($user, $purpose, $ipAddress, $userAgent, $correlationId);
            $this->sessions->create($user, $purpose, true);

            return true;
        }, 3);

        if (! $acknowledged) {
            $this->reject();
        }
    }

    private function generateRecoveryCode(int $length): string
    {
        $plain = '';
        $max = strlen(self::ALPHABET) - 1;

        for ($index = 0; $index < $length; $index++) {
            $plain .= self::ALPHABET[random_int(0, $max)];
        }

        return implode('-', str_split($plain, 4));
    }

    private function reject(): never
    {
        throw ValidationException::withMessages(['code' => 'The authentication code is invalid or expired.']);
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
            && $this->privilegedPermissions->authenticationRequiresMfa($user, $purpose)
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
