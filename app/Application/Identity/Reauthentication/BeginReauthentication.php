<?php

declare(strict_types=1);

namespace App\Application\Identity\Reauthentication;

use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Domain\Identity\Enums\MfaMethodType;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Services\Identity\CurrentAuthSessionValidator;
use App\Services\Identity\SafeReturnRoute;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Contracts\Session\Session;

final class BeginReauthentication
{
    public function __construct(
        private readonly PrimaryAuthenticationProvider $provider,
        private readonly CurrentAuthSessionValidator $sessions,
        private readonly SafeReturnRoute $safeReturnRoute,
        private readonly Session $session,
    ) {}

    public function handle(
        User $user,
        ?string $returnRoute,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        if ($this->sessions->current($user, false, false) === null) {
            throw new DomainRuleViolation('reauthentication_unavailable', ['Reauthentication is unavailable.']);
        }

        $hasRetainedMfa = UserMfaMethod::query()
            ->where('user_id', $user->getKey())
            ->where('type', MfaMethodType::Totp)
            ->whereNotNull('confirmed_at')
            ->whereNull('disabled_at')
            ->exists();

        if (! $hasRetainedMfa) {
            throw new DomainRuleViolation('reauthentication_unavailable', ['Reauthentication is unavailable.']);
        }

        $this->session->forget([
            'identity.auth_challenge',
            'identity.auth_purpose',
            'identity.otp_resend_available_at',
        ]);
        $this->session->put('identity.reauthentication_return_route', $this->safeReturnRoute->resolve($returnRoute));
        $authentication = $this->provider->begin(
            $user->email,
            AuthenticationPurpose::Reauthentication,
            $ipAddress,
            $userAgent,
            $correlationId,
        );

        if ($authentication->hasChallenge()) {
            $this->session->put('identity.auth_challenge', $authentication->challengeReference);
            $this->session->put('identity.auth_purpose', AuthenticationPurpose::Reauthentication->value);
        }
    }
}
