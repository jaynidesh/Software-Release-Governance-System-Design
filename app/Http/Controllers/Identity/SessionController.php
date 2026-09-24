<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Sessions\RevokeAllSessions;
use App\Application\Identity\Sessions\RevokeSession;
use App\Http\Controllers\Controller;
use App\Models\AuthSession;
use App\Models\User;
use App\Services\Identity\AuthenticatedSessionManager;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class SessionController extends Controller
{
    public function destroy(
        Request $request,
        AuthSession $authSession,
        RevokeSession $revoke,
        AuthenticatedSessionManager $sessions,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $correlationId = $request->attributes->get('correlation_id');
        $current = $revoke->handle(
            $actor,
            $authSession,
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );

        if ($current) {
            $sessions->logoutBrowser();

            return redirect()->route('login');
        }

        return redirect()->route('identity.security.index');
    }

    public function destroyAll(
        Request $request,
        RevokeAllSessions $revoke,
        AuthenticatedSessionManager $sessions,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $correlationId = $request->attributes->get('correlation_id');
        $revoke->handle(
            $actor,
            $actor,
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );
        $sessions->logoutBrowser();

        return redirect()->route('login');
    }
}
