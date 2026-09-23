<?php

declare(strict_types=1);

namespace App\Contracts\Identity;

use App\Models\AuthChallenge;
use App\Models\User;

interface OtpDelivery
{
    public function deliver(User $user, AuthChallenge $challenge, string $code): void;
}
