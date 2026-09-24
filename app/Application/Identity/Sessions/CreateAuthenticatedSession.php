<?php

declare(strict_types=1);

namespace App\Application\Identity\Sessions;

use App\Contracts\Identity\AuthenticatedSessionCreator;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\User;
use App\Services\Identity\AuthenticatedSessionManager;

final class CreateAuthenticatedSession implements AuthenticatedSessionCreator
{
    public function __construct(private readonly AuthenticatedSessionManager $sessions) {}

    public function create(User $user, AuthenticationPurpose $purpose, bool $mfaAuthenticated): void
    {
        if ($purpose === AuthenticationPurpose::Reauthentication) {
            $this->sessions->rekey($user, true);

            return;
        }

        $this->sessions->authenticate($user, $purpose, $mfaAuthenticated);
    }
}
