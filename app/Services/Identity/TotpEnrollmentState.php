<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Domain\Identity\Enums\MfaMethodType;
use App\Models\User;
use App\Models\UserMfaMethod;

final class TotpEnrollmentState
{
    public function isExpired(UserMfaMethod $method): bool
    {
        return $method->confirmed_at === null
            && $method->created_at !== null
            && $method->created_at->lte(now()->subMinutes((int) config('identity.totp.unconfirmed_ttl_minutes')));
    }

    public function discardProofFromEarlierPendingAuthentication(User $user): void
    {
        $method = UserMfaMethod::query()
            ->where('user_id', $user->getKey())
            ->where('type', MfaMethodType::Totp)
            ->whereNull('confirmed_at')
            ->whereNull('disabled_at')
            ->lockForUpdate()
            ->first();

        if ($method !== null && $method->recoveryCodes()->exists()) {
            $method->delete();
        }
    }
}
