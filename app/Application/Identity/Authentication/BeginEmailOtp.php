<?php

declare(strict_types=1);

namespace App\Application\Identity\Authentication;

use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
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

    public function resend(
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): bool {
        $challengeReference = $this->session->get('identity.auth_challenge');
        $purposeValue = $this->session->get('identity.auth_purpose');
        $purpose = is_string($purposeValue) ? AuthenticationPurpose::tryFrom($purposeValue) : null;

        if (! is_string($challengeReference) || $purpose === null) {
            $this->session->forget(['identity.auth_challenge', 'identity.auth_purpose']);

            return false;
        }

        $challenge = AuthChallenge::query()
            ->select(['id', 'public_id', 'user_id', 'purpose', 'created_at'])
            ->with('user:id,email')
            ->where('public_id', $challengeReference)
            ->where('purpose', $purpose)
            ->first();

        if ($challenge === null || $challenge->user === null || $challenge->created_at === null) {
            $this->session->forget(['identity.auth_challenge', 'identity.auth_purpose']);

            return false;
        }

        $delayPassed = now()->greaterThanOrEqualTo(
            $challenge->created_at->copy()->addSeconds((int) config('identity.otp.resend_seconds')),
        );
        $authentication = $this->provider->begin(
            $challenge->user->email,
            $purpose,
            $ipAddress,
            $userAgent,
            $correlationId,
        );

        if (! $authentication->hasChallenge()) {
            return false;
        }

        $this->session->put('identity.auth_challenge', $authentication->challengeReference);
        $this->session->put('identity.auth_purpose', $authentication->purpose?->value);

        return $delayPassed && $authentication->challengeReference !== $challengeReference;
    }
}
