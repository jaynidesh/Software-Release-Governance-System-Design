<?php

declare(strict_types=1);

namespace App\Contracts\Identity;

use App\Domain\Identity\Data\BeginAuthentication;
use App\Domain\Identity\Data\CompletedPrimaryAuthentication;
use App\Domain\Identity\Enums\AuthenticationPurpose;

interface PrimaryAuthenticationProvider
{
    public function begin(
        string $normalizedIdentifier,
        ?AuthenticationPurpose $purpose,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): BeginAuthentication;

    public function verify(
        string $challengeReference,
        string $code,
        AuthenticationPurpose $purpose,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): CompletedPrimaryAuthentication;
}
