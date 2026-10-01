<?php

declare(strict_types=1);

namespace App\Application\Identity\Authentication;

use App\Contracts\Identity\PrimaryAuthenticationProvider;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Str;

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

        $this->storePresentationState($authentication->challengeReference, $authentication->purpose);
    }

    public function resend(
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        $challengeReference = $this->session->get('identity.auth_challenge');
        $purposeValue = $this->session->get('identity.auth_purpose');
        $purpose = is_string($purposeValue) ? AuthenticationPurpose::tryFrom($purposeValue) : null;

        if (! is_string($challengeReference) || $purpose === null) {
            $this->storePresentationState(null, null);

            return;
        }

        $challenge = AuthChallenge::query()
            ->select(['id', 'public_id', 'user_id', 'purpose', 'created_at'])
            ->with('user:id,email')
            ->where('public_id', $challengeReference)
            ->where('purpose', $purpose)
            ->first();

        if ($challenge === null || $challenge->user === null || $challenge->created_at === null) {
            $this->storePresentationState($challengeReference, $purpose);

            return;
        }

        $authentication = $this->provider->begin(
            $challenge->user->email,
            $purpose,
            $ipAddress,
            $userAgent,
            $correlationId,
        );

        $this->storePresentationState(
            $authentication->challengeReference ?? $challengeReference,
            $authentication->purpose ?? $purpose,
        );
    }

    private function storePresentationState(
        ?string $challengeReference,
        ?AuthenticationPurpose $purpose,
    ): void {
        $this->session->put([
            'identity.auth_challenge' => $challengeReference ?? strtolower((string) Str::ulid()),
            'identity.auth_purpose' => ($purpose ?? AuthenticationPurpose::Login)->value,
            'identity.otp_resend_available_at' => now()
                ->addSeconds((int) config('identity.otp.resend_seconds'))
                ->getTimestampMs(),
        ]);
    }
}
