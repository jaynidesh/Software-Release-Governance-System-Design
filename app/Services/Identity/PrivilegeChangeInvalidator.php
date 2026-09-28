<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\PendingAuthentication;
use App\Models\User;
use Illuminate\Support\Facades\DB;

final class PrivilegeChangeInvalidator
{
    public function invalidate(User $user): void
    {
        $sessionIds = AuthSession::query()
            ->where('user_id', $user->getKey())
            ->lockForUpdate()
            ->pluck('session_id');

        DB::table('sessions')->whereIn('id', $sessionIds)->delete();
        AuthSession::query()->where('user_id', $user->getKey())->delete();
        AuthChallenge::query()
            ->where('user_id', $user->getKey())
            ->whereNull('consumed_at')
            ->whereNull('invalidated_at')
            ->update(['invalidated_at' => now()]);
        PendingAuthentication::query()
            ->where('user_id', $user->getKey())
            ->whereNull('completed_at')
            ->whereNull('invalidated_at')
            ->update(['invalidated_at' => now()]);
        $user->increment('session_version');
        $user->refresh();
    }
}
