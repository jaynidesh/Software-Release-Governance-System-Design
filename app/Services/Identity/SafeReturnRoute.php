<?php

declare(strict_types=1);

namespace App\Services\Identity;

use Illuminate\Support\Facades\Route;

final class SafeReturnRoute
{
    /** @var list<string> */
    private const ALLOWED = [
        'home',
        'identity.security.index',
        'admin.applications.index',
        'admin.users.index',
        'admin.roles.index',
        'admin.role-assignments.index',
    ];

    public function resolve(?string $routeName): string
    {
        if ($routeName !== null && in_array($routeName, self::ALLOWED, true) && Route::has($routeName)) {
            return $routeName;
        }

        return 'identity.security.index';
    }
}
