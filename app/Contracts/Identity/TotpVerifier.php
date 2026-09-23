<?php

declare(strict_types=1);

namespace App\Contracts\Identity;

interface TotpVerifier
{
    public function generateSecret(): string;

    public function provisioningUri(string $secret, string $accountName): string;

    /** Returns the matched RFC 6238 timestep, or null when the code is invalid. */
    public function verify(string $secret, string $code, ?int $timestamp = null): ?int;
}
