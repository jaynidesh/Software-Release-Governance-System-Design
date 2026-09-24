<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Models\User;
use App\Services\Identity\CurrentAuthSessionValidator;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class RequireFreshReauthentication
{
    public function __construct(private readonly CurrentAuthSessionValidator $sessions) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user instanceof User || ! $this->sessions->hasFreshMfa($user)) {
            $request->session()->put('identity.reauthentication_return_route', 'identity.security.index');

            return redirect()->route('identity.reauthentication.show')
                ->with('status', 'Complete reauthentication to continue.');
        }

        return $next($request);
    }
}
