<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Application\Identity\Sessions\RekeyAuthenticatedSession;
use App\Contracts\Identity\AuthenticatedSessionCreator;
use App\Contracts\Identity\OtpDelivery;
use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Domain\Identity\Data\BeginAuthentication;
use App\Domain\Identity\Data\CompletedPrimaryAuthentication;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\UserState;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

final class EmailOtpAuthenticationProvider implements PrimaryAuthenticationProvider
{
    public function __construct(
        private readonly OtpHasher $hasher,
        private readonly AuthenticationThrottle $throttle,
        private readonly OtpDelivery $delivery,
        private readonly IdentityEventRecorder $events,
        private readonly AccountLockout $lockout,
        private readonly Session $session,
        private readonly PrivilegedPermissionResolver $privilegedPermissions,
        private readonly TotpEnrollmentState $enrollmentState,
        private readonly AuthenticatedSessionCreator $authenticatedSessions,
        private readonly RekeyAuthenticatedSession $rekeyAuthenticatedSession,
    ) {}

    public function begin(
        string $normalizedIdentifier,
        ?AuthenticationPurpose $purpose,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): BeginAuthentication {
        $fallbackPurpose = $purpose ?? AuthenticationPurpose::Login;

        if (! $this->throttle->allowsRequest($normalizedIdentifier, $ipAddress)) {
            $this->events->login(
                $normalizedIdentifier,
                $fallbackPurpose,
                'OTP_REQUEST_THROTTLED',
                null,
                $ipAddress,
                $userAgent,
                $correlationId,
            );

            return new BeginAuthentication(null, null);
        }

        return DB::transaction(function () use (
            $normalizedIdentifier,
            $purpose,
            $fallbackPurpose,
            $ipAddress,
            $userAgent,
            $correlationId,
        ): BeginAuthentication {
            $user = User::query()
                ->where('email', $normalizedIdentifier)
                ->lockForUpdate()
                ->first();
            $resolvedPurpose = $this->resolvePurpose($user, $purpose);

            if ($user === null || $resolvedPurpose === null || ! $this->eligible($user, $resolvedPurpose)) {
                $this->events->login(
                    $normalizedIdentifier,
                    $resolvedPurpose ?? $fallbackPurpose,
                    'OTP_REQUEST_IGNORED',
                    $user,
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                return new BeginAuthentication(null, null);
            }

            $openChallenge = AuthChallenge::query()
                ->where('user_id', $user->getKey())
                ->where('purpose', $resolvedPurpose)
                ->whereNull('consumed_at')
                ->whereNull('invalidated_at')
                ->lockForUpdate()
                ->first();

            if ($openChallenge !== null
                && $openChallenge->created_at !== null
                && now()->subSeconds((int) config('identity.otp.resend_seconds'))->isBefore($openChallenge->created_at)) {
                $this->events->login(
                    $normalizedIdentifier,
                    $resolvedPurpose,
                    'OTP_REQUEST_REUSED',
                    $user,
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                return new BeginAuthentication($openChallenge->public_id, $resolvedPurpose);
            }

            if ($openChallenge !== null) {
                $openChallenge->update(['invalidated_at' => now()]);
            }

            PendingAuthentication::query()
                ->where('user_id', $user->getKey())
                ->whereNull('completed_at')
                ->whereNull('invalidated_at')
                ->update(['invalidated_at' => now()]);

            $code = $this->generateCode();
            $challengeReference = strtolower((string) Str::ulid());
            $challenge = new AuthChallenge([
                'user_id' => $user->getKey(),
                'purpose' => $resolvedPurpose,
                'code_hmac' => $this->hasher->hash(
                    $code,
                    $challengeReference,
                    (int) $user->getKey(),
                    $resolvedPurpose,
                ),
                'expires_at' => now()->addMinutes((int) config('identity.otp.ttl_minutes')),
                'request_ip' => $ipAddress,
                'user_agent' => $userAgent === null ? null : mb_substr($userAgent, 0, 500),
                'correlation_id' => $correlationId,
            ]);
            $challenge->public_id = $challengeReference;
            $challenge->save();

            $this->events->login(
                $normalizedIdentifier,
                $resolvedPurpose,
                'OTP_REQUEST_ACCEPTED',
                $user,
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $this->events->security(
                'identity.otp.requested',
                null,
                $user,
                ['challenge_reference' => $challenge->public_id, 'purpose' => $resolvedPurpose->value],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $this->delivery->deliver($user, $challenge, $code);

            return new BeginAuthentication($challenge->public_id, $resolvedPurpose);
        }, 3);
    }

    public function verify(
        string $challengeReference,
        string $code,
        AuthenticationPurpose $purpose,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): CompletedPrimaryAuthentication {
        $challengeIdentity = AuthChallenge::query()
            ->select(['id', 'user_id'])
            ->where('public_id', $challengeReference)
            ->first();

        if ($challengeIdentity === null) {
            $this->events->security(
                'identity.otp.verification_failed',
                null,
                null,
                ['reason' => 'unresolved_challenge'],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $this->events->security(
                'identity.authentication.failed',
                null,
                null,
                ['purpose' => $purpose->value],
                $ipAddress,
                $userAgent,
                $correlationId,
            );

            $this->rejectCode();
        }

        $completed = DB::transaction(function () use (
            $challengeIdentity,
            $challengeReference,
            $code,
            $purpose,
            $ipAddress,
            $userAgent,
            $correlationId,
        ): ?CompletedPrimaryAuthentication {
            $user = User::query()->whereKey($challengeIdentity->user_id)->lockForUpdate()->first();
            $challenge = AuthChallenge::query()
                ->whereKey($challengeIdentity->getKey())
                ->lockForUpdate()
                ->first();

            if ($user === null || $challenge === null || ! $this->challengeCanBeVerified($user, $challenge, $purpose)) {
                if ($challenge !== null
                    && now()->greaterThanOrEqualTo($challenge->expires_at)
                    && $challenge->invalidated_at === null) {
                    $challenge->update(['invalidated_at' => now()]);
                    $this->events->security(
                        'identity.otp.expired',
                        null,
                        $user,
                        ['challenge_reference' => $challengeReference],
                        $ipAddress,
                        $userAgent,
                        $correlationId,
                    );
                }

                $this->recordVerificationFailure(
                    $user,
                    $purpose,
                    'OTP_VERIFICATION_REJECTED',
                    $challengeReference,
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                return null;
            }

            if (! $this->hasher->verify(
                $code,
                $challenge->public_id,
                (int) $user->getKey(),
                $this->challengePurpose($challenge),
                $challenge->code_hmac,
            )) {
                $failedAttempts = $challenge->failed_attempts + 1;
                $challenge->forceFill([
                    'failed_attempts' => $failedAttempts,
                    'invalidated_at' => $failedAttempts >= (int) config('identity.otp.max_attempts') ? now() : null,
                ])->save();
                $locked = $this->lockout->recordFailure($user);
                $this->recordVerificationFailure(
                    $user,
                    $purpose,
                    'OTP_VERIFICATION_FAILED',
                    $challengeReference,
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                if ($locked) {
                    $this->events->security(
                        'identity.account.locked',
                        null,
                        $user,
                        [],
                        $ipAddress,
                        $userAgent,
                        $correlationId,
                    );
                }

                return null;
            }

            $challenge->update(['consumed_at' => now()]);
            $this->events->security(
                'identity.otp.consumed',
                null,
                $user,
                ['challenge_reference' => $challenge->public_id, 'purpose' => $purpose->value],
                $ipAddress,
                $userAgent,
                $correlationId,
            );

            $requiresMfa = $this->privilegedPermissions->authenticationRequiresMfa($user, $purpose);

            if ($purpose === AuthenticationPurpose::Reauthentication && ! $requiresMfa) {
                $this->recordVerificationFailure(
                    $user,
                    $purpose,
                    'OTP_VERIFICATION_REJECTED',
                    $challengeReference,
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );

                return null;
            }

            if ($requiresMfa) {
                return $this->completePendingPrimary(
                    $user,
                    $challenge,
                    $purpose,
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );
            }

            return $this->completeOrdinaryAuthentication(
                $user,
                $challenge,
                $purpose,
                $ipAddress,
                $userAgent,
                $correlationId,
            );
        }, 3);

        if ($completed === null) {
            $this->rejectCode();
        }

        return $completed;
    }

    private function challengeCanBeVerified(
        User $user,
        AuthChallenge $challenge,
        AuthenticationPurpose $purpose,
    ): bool {
        return $this->challengePurpose($challenge) === $purpose
            && $challenge->delivered_at !== null
            && $challenge->consumed_at === null
            && $challenge->invalidated_at === null
            && now()->isBefore($challenge->expires_at)
            && ! $this->lockout->isLocked($user)
            && $this->eligible($user, $purpose);
    }

    private function completeOrdinaryAuthentication(
        User $user,
        AuthChallenge $challenge,
        AuthenticationPurpose $purpose,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): CompletedPrimaryAuthentication {
        if ($purpose === AuthenticationPurpose::Activation) {
            $user->forceFill([
                'state' => UserState::Active,
                'email_verified_at' => now(),
                'activated_at' => now(),
            ]);
            $this->events->security(
                'identity.invitation.activated',
                null,
                $user,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
        }

        $user->forceFill(['last_login_at' => now()])->save();
        $this->lockout->reset($user);
        $this->authenticatedSessions->create($user, $purpose, false);
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

        return new CompletedPrimaryAuthentication($user, $challenge, null, true);
    }

    private function completePendingPrimary(
        User $user,
        AuthChallenge $challenge,
        AuthenticationPurpose $purpose,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): CompletedPrimaryAuthentication {
        if ($purpose === AuthenticationPurpose::Activation && $user->email_verified_at === null) {
            $user->forceFill(['email_verified_at' => now()])->save();
        }

        if ($purpose === AuthenticationPurpose::Reauthentication) {
            $this->rekeyAuthenticatedSession->handle($user);
        } else {
            $this->session->invalidate();
            $this->session->regenerateToken();
        }
        $this->enrollmentState->discardProofFromEarlierPendingAuthentication($user);
        PendingAuthentication::query()
            ->where('user_id', $user->getKey())
            ->where('purpose', $purpose)
            ->whereNull('completed_at')
            ->whereNull('invalidated_at')
            ->update(['invalidated_at' => now()]);
        $pending = PendingAuthentication::query()->create([
            'user_id' => $user->getKey(),
            'auth_challenge_id' => $challenge->getKey(),
            'purpose' => $purpose,
            'session_id_hmac' => $this->hasher->hashSessionId($this->session->getId()),
            'user_session_version' => $user->session_version,
            'expires_at' => now()->addMinutes((int) config('identity.pending_auth_ttl_minutes')),
            'request_ip' => $ipAddress,
            'user_agent' => $userAgent === null ? null : mb_substr($userAgent, 0, 500),
            'correlation_id' => $correlationId,
        ]);
        $this->session->put('identity.pending_authentication', $pending->public_id);
        $this->events->login(
            $user->email,
            $purpose,
            'PRIMARY_AUTHENTICATION_SUCCEEDED',
            $user,
            $ipAddress,
            $userAgent,
            $correlationId,
        );
        $this->events->security(
            'identity.authentication.primary_succeeded',
            null,
            $user,
            ['pending_reference' => $pending->public_id, 'purpose' => $purpose->value],
            $ipAddress,
            $userAgent,
            $correlationId,
        );

        return new CompletedPrimaryAuthentication($user, $challenge, $pending, false);
    }

    private function recordVerificationFailure(
        ?User $user,
        AuthenticationPurpose $purpose,
        string $resultCode,
        string $challengeReference,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        if ($user !== null) {
            $this->events->login(
                $user->email,
                $purpose,
                $resultCode,
                $user,
                $ipAddress,
                $userAgent,
                $correlationId,
            );
        }

        $this->events->security(
            'identity.otp.verification_failed',
            null,
            $user,
            ['challenge_reference' => $challengeReference],
            $ipAddress,
            $userAgent,
            $correlationId,
        );
        $this->events->security(
            'identity.authentication.failed',
            null,
            $user,
            ['purpose' => $purpose->value],
            $ipAddress,
            $userAgent,
            $correlationId,
        );
    }

    private function rejectCode(): never
    {
        throw ValidationException::withMessages(['code' => 'The code is invalid or expired.']);
    }

    private function resolvePurpose(?User $user, ?AuthenticationPurpose $requestedPurpose): ?AuthenticationPurpose
    {
        if ($requestedPurpose !== null) {
            return $requestedPurpose;
        }

        return match ($user === null ? null : $this->userState($user)) {
            UserState::Invited => AuthenticationPurpose::Activation,
            UserState::Active => AuthenticationPurpose::Login,
            default => null,
        };
    }

    private function eligible(User $user, AuthenticationPurpose $purpose): bool
    {
        if ($user->locked_until !== null && now()->isBefore($user->locked_until)) {
            return false;
        }

        return match ($purpose) {
            AuthenticationPurpose::Activation => $this->userState($user) === UserState::Invited
                && $user->invitation_expires_at !== null
                && now()->isBefore($user->invitation_expires_at),
            AuthenticationPurpose::Login, AuthenticationPurpose::Reauthentication => $this->userState($user) === UserState::Active
                && $user->email_verified_at !== null,
        };
    }

    private function challengePurpose(AuthChallenge $challenge): AuthenticationPurpose
    {
        return AuthenticationPurpose::from((string) $challenge->getRawOriginal('purpose'));
    }

    private function userState(User $user): UserState
    {
        return UserState::from((string) $user->getRawOriginal('state'));
    }

    private function generateCode(): string
    {
        $digits = (int) config('identity.otp.digits');
        $maximum = (10 ** $digits) - 1;

        return str_pad((string) random_int(0, $maximum), $digits, '0', STR_PAD_LEFT);
    }
}
