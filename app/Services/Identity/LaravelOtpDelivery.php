<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Contracts\Identity\OtpDelivery;
use App\Models\AuthChallenge;
use App\Models\User;
use App\Notifications\Identity\EmailOtpNotification;
use Illuminate\Support\Facades\DB;
use Throwable;

final class LaravelOtpDelivery implements OtpDelivery
{
    public function __construct(private readonly OtpDeliveryFailureReporter $failures) {}

    public function deliver(User $user, AuthChallenge $challenge, string $code): void
    {
        DB::afterCommit(function () use ($user, $challenge, $code): void {
            try {
                $user->notify(new EmailOtpNotification($challenge->public_id, $code));
            } catch (Throwable $exception) {
                $this->failures->report($user, $challenge, 'mail', $exception);
            }
        });
    }
}
