<?php

declare(strict_types=1);

namespace Tests\Unit\Identity;

use App\Services\Identity\OtpPhpTotpVerifier;
use PHPUnit\Framework\TestCase;

final class OtpPhpTotpVerifierTest extends TestCase
{
    private const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public function test_rfc_6238_defaults_return_the_matched_timestep(): void
    {
        $verifier = new OtpPhpTotpVerifier(1);

        self::assertSame(1, $verifier->verify(self::RFC_SECRET, '287082', 59));
        self::assertNull($verifier->verify(self::RFC_SECRET, '287082', 90));
    }

    public function test_window_is_never_wider_than_one_adjacent_interval(): void
    {
        $verifier = new OtpPhpTotpVerifier(50);

        self::assertSame(1, $verifier->verify(self::RFC_SECRET, '287082', 89));
        self::assertNull($verifier->verify(self::RFC_SECRET, '287082', 119));
    }
}
