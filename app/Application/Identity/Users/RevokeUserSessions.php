<?php

declare(strict_types=1);

namespace App\Application\Identity\Users;

use App\Application\Identity\Sessions\RevokeAllSessions;
use App\Models\User;

final class RevokeUserSessions
{
    public function __construct(private readonly RevokeAllSessions $revokeAllSessions) {}

    public function handle(
        User $actor,
        User $target,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): void {
        $this->revokeAllSessions->handle($actor, $target, $ipAddress, $userAgent, $correlationId);
    }
}
