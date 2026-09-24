<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Models\AuthSession;
use Illuminate\Http\Request;

final class SessionActivityRecorder
{
    private const WRITE_INTERVAL_SECONDS = 60;

    public function record(AuthSession $authSession, Request $request): void
    {
        if (! $this->isApplicationActivity($request)) {
            return;
        }

        AuthSession::query()
            ->whereKey($authSession->getKey())
            ->where('last_seen_at', '<=', now()->subSeconds(self::WRITE_INTERVAL_SECONDS))
            ->update(['last_seen_at' => now()]);
    }

    private function isApplicationActivity(Request $request): bool
    {
        if ($request->is('health', 'ready', 'up')) {
            return false;
        }

        $purpose = mb_strtolower($request->header('Purpose', '').' '.$request->header('Sec-Purpose', ''));

        return ! str_contains($purpose, 'prefetch');
    }
}
