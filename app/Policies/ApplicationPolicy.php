<?php

declare(strict_types=1);

namespace App\Policies;

use App\Contracts\Identity\AuthorizationService;
use App\Models\Application;
use App\Models\User;

final class ApplicationPolicy
{
    public function __construct(private readonly AuthorizationService $authorization) {}

    public function viewAny(User $user): bool
    {
        return $this->authorization->allows($user, 'admin.applications', null, false);
    }

    public function view(User $user, Application $application): bool
    {
        return $this->authorization->allows($user, 'admin.applications', null, false);
    }

    public function create(User $user): bool
    {
        return $this->authorization->allows($user, 'admin.applications', null, true);
    }

    public function update(User $user, Application $application): bool
    {
        return $this->authorization->allows($user, 'admin.applications', null, true);
    }

    public function changeState(User $user, Application $application): bool
    {
        return $this->authorization->allows($user, 'admin.applications', null, true);
    }
}
