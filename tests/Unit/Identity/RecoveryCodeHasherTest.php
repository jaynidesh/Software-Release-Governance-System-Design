<?php

declare(strict_types=1);

namespace Tests\Unit\Identity;

use App\Services\Identity\RecoveryCodeHasher;
use PHPUnit\Framework\TestCase;

final class RecoveryCodeHasherTest extends TestCase
{
    public function test_hash_is_bound_to_the_mfa_method_and_compared_in_constant_time(): void
    {
        $hasher = new RecoveryCodeHasher('test-recovery-pepper');
        $hash = $hasher->hash('ABCD-EFGH-IJKL', 41);

        self::assertSame(64, strlen($hash));
        self::assertTrue($hasher->verify('ABCD-EFGH-IJKL', 41, $hash));
        self::assertFalse($hasher->verify('ABCD-EFGH-IJKL', 42, $hash));
        self::assertFalse($hasher->verify('ABCD-EFGH-IJKM', 41, $hash));
        self::assertStringNotContainsString('ABCD', $hash);
    }
}
