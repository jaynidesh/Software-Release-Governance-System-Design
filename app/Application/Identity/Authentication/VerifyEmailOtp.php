<?php

declare(strict_types=1);

namespace App\Application\Identity\Authentication;

use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Domain\Identity\Data\CompletedPrimaryAuthentication;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use Illuminate\Contracts\Session\Session;
use Illuminate\Validation\ValidationException;

final class VerifyEmailOtp
{
    public function __construct(
        private readonly PrimaryAuthenticationProvider $provider,
        private readonly Session $session,
    ) {}

    public function handle(
        string $code,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): CompletedPrimaryAuthentication {
        $challengeReference = $this->session->get('identity.auth_challenge');
        $purposeValue = $this->session->get('identity.auth_purpose');
        $purpose = is_string($purposeValue) ? AuthenticationPurpose::tryFrom($purposeValue) : null;

        if (! is_string($challengeReference) || $purpose === null) {
            throw ValidationException::withMessages(['code' => 'The code is invalid or expired.']);
        }

        $completed = $this->provider->verify(
            $challengeReference,
            $code,
            $purpose,
            $ipAddress,
            $userAgent,
            $correlationId,
        );

        $this->session->forget(['identity.auth_challenge', 'identity.auth_purpose']);

        return $completed;
    }
}
