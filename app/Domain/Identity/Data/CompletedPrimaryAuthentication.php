<?php

declare(strict_types=1);

namespace App\Domain\Identity\Data;

use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\User;

final readonly class CompletedPrimaryAuthentication
{
    public function __construct(
        public User $user,
        public AuthChallenge $challenge,
        public ?PendingAuthentication $pendingAuthentication,
        public bool $authenticated,
    ) {}

    public function requiresAdditionalProof(): bool
    {
        return $this->pendingAuthentication !== null;
    }
}
