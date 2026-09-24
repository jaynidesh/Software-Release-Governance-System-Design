<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Models\User;
use App\Services\Identity\CurrentAuthSessionValidator;
use App\Services\Identity\SafeReturnRoute;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class RequireFreshReauthentication
{
    public function __construct(
        private readonly CurrentAuthSessionValidator $sessions,
        private readonly SafeReturnRoute $safeReturnRoute,
    ) {}

    /**
     * The optional middleware parameter is an allow-listed named GET landing route,
     * for example `fresh.reauth:admin.applications.index`.
     */
    public function handle(
        Request $request,
        Closure $next,
        string $returnRoute = 'identity.security.index',
    ): Response {
        $user = $request->user();

        if (! $user instanceof User || ! $this->sessions->hasFreshMfa($user)) {
            $request->session()->put(
                'identity.reauthentication_return_route',
                $this->safeReturnRoute->resolve($returnRoute),
            );

            $response = redirect()->route('identity.reauthentication.show')
                ->with('status', 'Complete reauthentication to continue.');
            $response->headers->set('Cache-Control', 'no-store, private');

            return $response;
        }

        return $next($request);
    }
}
