<?php

declare(strict_types=1);

namespace App\Application\Identity\Authentication;

use App\Contracts\Identity\PrimaryAuthenticationProvider;
use Illuminate\Contracts\Session\Session;

final class BeginEmailOtp
{
    public function __construct(
        private readonly PrimaryAuthenticationProvider $provider,
        private readonly Session $session,
    ) {}

    public function handle(
        string $normalizedEmail,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        $authentication = $this->provider->begin(
            $normalizedEmail,
            null,
            $ipAddress,
            $userAgent,
            $correlationId,
        );

        $this->session->forget(['identity.auth_challenge', 'identity.auth_purpose']);

        if ($authentication->hasChallenge()) {
            $this->session->put('identity.auth_challenge', $authentication->challengeReference);
            $this->session->put('identity.auth_purpose', $authentication->purpose?->value);
        }
    }
}
