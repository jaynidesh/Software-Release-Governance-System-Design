<?php

declare(strict_types=1);

namespace App\Contracts\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\User;

interface AuthenticatedSessionCreator
{
    public function create(User $user, AuthenticationPurpose $purpose, bool $mfaAuthenticated): void;
}
