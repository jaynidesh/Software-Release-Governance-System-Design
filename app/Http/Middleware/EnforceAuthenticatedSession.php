<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Models\User;
use App\Services\Identity\AuthenticatedSessionManager;
use App\Services\Identity\CurrentAuthSessionValidator;
use App\Services\Identity\SessionActivityRecorder;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class EnforceAuthenticatedSession
{
    public function __construct(
        private readonly CurrentAuthSessionValidator $validator,
        private readonly SessionActivityRecorder $activity,
        private readonly AuthenticatedSessionManager $sessions,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user instanceof User) {
            return $next($request);
        }

        $authSession = $this->validator->current($user, false, false);

        if ($authSession === null) {
            $this->sessions->invalidateCurrent($user);

            return redirect()->route('login')
                ->with('status', 'Your session is no longer available. Please sign in again.');
        }

        $this->activity->record($authSession, $request);
        $request->attributes->set('identity.auth_session', $authSession);

        return $next($request);
    }
}
