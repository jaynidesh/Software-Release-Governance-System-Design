<?php

declare(strict_types=1);

namespace App\Domain\Identity\Data;

use App\Domain\Identity\Enums\AuthenticationPurpose;

final readonly class BeginAuthentication
{
    public function __construct(
        public ?string $challengeReference,
        public ?AuthenticationPurpose $purpose,
    ) {}

    public function hasChallenge(): bool
    {
        return $this->challengeReference !== null && $this->purpose !== null;
    }
}
