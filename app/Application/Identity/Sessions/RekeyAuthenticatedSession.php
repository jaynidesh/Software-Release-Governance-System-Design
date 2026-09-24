<?php

declare(strict_types=1);

namespace App\Application\Identity\Sessions;

use App\Models\User;
use App\Services\Identity\AuthenticatedSessionManager;

final class RekeyAuthenticatedSession
{
    public function __construct(private readonly AuthenticatedSessionManager $sessions) {}

    public function handle(User $user): void
    {
        $this->sessions->rekey($user, false);
    }
}
