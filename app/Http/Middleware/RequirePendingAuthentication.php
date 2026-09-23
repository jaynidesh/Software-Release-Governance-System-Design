<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Domain\Identity\Enums\UserState;
use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Services\Identity\AccountLockout;
use App\Services\Identity\OtpHasher;
use App\Services\Identity\PrivilegedPermissionResolver;
use App\Services\Identity\TotpEnrollmentState;
use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

final class RequirePendingAuthentication
{
    public function __construct(
        private readonly OtpHasher $hasher,
        private readonly PrivilegedPermissionResolver $privilegedPermissions,
        private readonly AccountLockout $lockout,
        private readonly TotpEnrollmentState $enrollmentState,
    ) {}

    public function handle(Request $request, Closure $next, string $requiredStep): Response
    {
        $reference = $request->session()->get('identity.pending_authentication');
        $pending = is_string($reference)
            ? PendingAuthentication::query()->where('public_id', $reference)->first()
            : null;
        $user = $pending === null ? null : User::query()->whereKey($pending->user_id)->first();

        if (! $this->valid($request, $pending, $user)) {
            if ($pending !== null && $pending->completed_at === null && $pending->invalidated_at === null) {
                $pending->forceFill(['invalidated_at' => now()])->save();
            }

            $request->session()->forget('identity.pending_authentication');

            return $this->noStoreRedirect('login');
        }

        if (! $user instanceof User) {
            return $this->noStoreRedirect('login');
        }

        $actualStep = $this->nextStep($user);

        if ($actualStep !== $requiredStep) {
            return $this->noStoreRedirect(match ($actualStep) {
                'verify' => 'identity.mfa.verify.create',
                'recovery' => 'identity.mfa.recovery.create',
                default => 'identity.mfa.enroll.create',
            });
        }

        $request->attributes->set('identity.pending', $pending);

        return $next($request);
    }

    private function valid(Request $request, ?PendingAuthentication $pending, ?User $user): bool
    {
        if ($pending === null || $user === null
            || $pending->completed_at !== null || $pending->invalidated_at !== null
            || now()->greaterThanOrEqualTo($pending->expires_at)
            || $pending->user_session_version !== $user->session_version
            || ! hash_equals($pending->session_id_hmac, $this->hasher->hashSessionId($request->session()->getId()))
            || $this->lockout->isLocked($user)
            || ! $this->eligible($user, $this->purpose($pending))
            || ! $this->privilegedPermissions->authenticationRequiresMfa($user, $this->purpose($pending))) {
            return false;
        }

        return ! AuthChallenge::query()
            ->where('user_id', $user->getKey())
            ->where('purpose', $pending->purpose)
            ->where('id', '>', $pending->auth_challenge_id)
            ->exists();
    }

    private function eligible(User $user, AuthenticationPurpose $purpose): bool
    {
        $state = $this->state($user);

        return match ($purpose) {
            AuthenticationPurpose::Activation => $state === UserState::Invited
                && $user->email_verified_at !== null
                && $user->invitation_expires_at !== null
                && now()->isBefore($user->invitation_expires_at),
            AuthenticationPurpose::Login, AuthenticationPurpose::Reauthentication => $state === UserState::Active,
        };
    }

    private function nextStep(User $user): string
    {
        return DB::transaction(function () use ($user): string {
            User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $method = UserMfaMethod::query()
                ->where('user_id', $user->getKey())
                ->where('type', MfaMethodType::Totp)
                ->whereNull('disabled_at')
                ->lockForUpdate()
                ->first();

            if ($method !== null && $this->enrollmentState->isExpired($method)) {
                $method->delete();

                return 'enroll';
            }

            if ($method?->confirmed_at !== null) {
                return 'verify';
            }

            if ($method !== null && $method->recoveryCodes()->exists()) {
                return 'recovery';
            }

            return 'enroll';
        }, 3);
    }

    private function noStoreRedirect(string $route): RedirectResponse
    {
        $response = redirect()->route($route);
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
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
