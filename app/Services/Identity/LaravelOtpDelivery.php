<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Contracts\Identity\OtpDelivery;
use App\Models\AuthChallenge;
use App\Models\User;
use App\Notifications\Identity\EmailOtpNotification;

final class LaravelOtpDelivery implements OtpDelivery
{
    public function deliver(User $user, AuthChallenge $challenge, string $code): void
    {
        $user->notify(new EmailOtpNotification($challenge->public_id, $code));
    }
}
