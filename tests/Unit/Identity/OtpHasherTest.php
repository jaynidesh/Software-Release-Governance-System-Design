<?php

declare(strict_types=1);

namespace Tests\Unit\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Services\Identity\OtpHasher;
use PHPUnit\Framework\TestCase;

final class OtpHasherTest extends TestCase
{
    public function test_hash_binds_code_to_challenge_user_and_purpose(): void
    {
        $hasher = new OtpHasher('test-pepper-at-least-thirty-two-bytes');

        $hash = $hasher->hash('123456', 'challenge-01', 42, AuthenticationPurpose::Login);

        self::assertSame('11c6d48d90e561e3c246cc43f6b5299529d86a90852aff9d8ce2142115fc2e50', $hash);
        self::assertTrue($hasher->verify(
            '123456',
            'challenge-01',
            42,
            AuthenticationPurpose::Login,
            $hash,
        ));
        self::assertFalse($hasher->verify('654321', 'challenge-01', 42, AuthenticationPurpose::Login, $hash));
        self::assertFalse($hasher->verify('123456', 'challenge-02', 42, AuthenticationPurpose::Login, $hash));
        self::assertFalse($hasher->verify('123456', 'challenge-01', 43, AuthenticationPurpose::Login, $hash));
        self::assertFalse($hasher->verify('123456', 'challenge-01', 42, AuthenticationPurpose::Activation, $hash));
    }

    public function test_verification_rejects_malformed_or_non_matching_hashes(): void
    {
        $hasher = new OtpHasher('test-pepper-at-least-thirty-two-bytes');

        self::assertFalse($hasher->verify('123456', 'challenge-01', 42, AuthenticationPurpose::Login, ''));
        self::assertFalse($hasher->verify('123456', 'challenge-01', 42, AuthenticationPurpose::Login, str_repeat('0', 64)));
    }
}
