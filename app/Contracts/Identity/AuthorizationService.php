<?php

declare(strict_types=1);

namespace App\Contracts\Identity;

use App\Models\Application;
use App\Models\User;

interface AuthorizationService
{
    public function allows(
        User $user,
        string $permission,
        ?Application $application,
        bool $requiresFreshReauthentication,
    ): bool;
}
