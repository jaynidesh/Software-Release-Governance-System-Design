<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Authentication;

use App\Application\Identity\Authentication\CancelPendingAuthentication;
use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class PendingAuthenticationCancellationController extends Controller
{
    public function __invoke(Request $request, CancelPendingAuthentication $cancel): RedirectResponse
    {
        $correlationId = $request->attributes->get('correlation_id');
        $cancel->handle(
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );
        $response = redirect()->route('login');
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }
}
