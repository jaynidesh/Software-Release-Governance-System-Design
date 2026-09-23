<?php

declare(strict_types=1);

namespace App\Services\Identity;

final class RecoveryCodeHasher
{
    public function __construct(private readonly ?string $pepper = null) {}

    public function hash(string $code, int $mfaMethodId): string
    {
        return hash_hmac('sha256', implode("\0", [
            'recovery-code',
            (string) $mfaMethodId,
            mb_strtoupper(trim($code)),
        ]), $this->pepper ?? (string) config('identity.otp.pepper'));
    }

    public function verify(string $code, int $mfaMethodId, string $expectedHash): bool
    {
        return hash_equals($expectedHash, $this->hash($code, $mfaMethodId));
    }
}
