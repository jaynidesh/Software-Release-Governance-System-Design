<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;

final class OtpHasher
{
    public function __construct(private readonly ?string $pepper = null) {}

    public function hash(
        string $code,
        string $challengePublicId,
        int $userId,
        AuthenticationPurpose $purpose,
    ): string {
        return hash_hmac('sha256', implode("\0", [
            'otp',
            $challengePublicId,
            (string) $userId,
            $purpose->value,
            $code,
        ]), $this->resolvedPepper());
    }

    public function verify(
        string $code,
        string $challengePublicId,
        int $userId,
        AuthenticationPurpose $purpose,
        string $expectedHash,
    ): bool {
        return hash_equals(
            $expectedHash,
            $this->hash($code, $challengePublicId, $userId, $purpose),
        );
    }

    public function hashIdentifier(string $normalizedIdentifier): string
    {
        return hash_hmac(
            'sha256',
            implode("\0", ['identifier', $normalizedIdentifier]),
            $this->resolvedPepper(),
        );
    }

    public function hashSessionId(string $sessionId): string
    {
        return hash_hmac('sha256', implode("\0", ['session', $sessionId]), $this->resolvedPepper());
    }

    private function resolvedPepper(): string
    {
        return $this->pepper ?? (string) config('identity.otp.pepper');
    }
}
