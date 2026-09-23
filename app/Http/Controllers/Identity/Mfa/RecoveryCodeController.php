<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Mfa;

use App\Application\Identity\Mfa\ConfirmTotpEnrollment;
use App\Http\Controllers\Controller;
use App\Models\PendingAuthentication;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

final class RecoveryCodeController extends Controller
{
    public function create(): Response
    {
        return response()->view('identity.mfa.recovery-codes', ['codes' => [], 'initial' => false])
            ->header('Cache-Control', 'no-store, private');
    }

    public function store(Request $request, ConfirmTotpEnrollment $confirm): RedirectResponse
    {
        $request->validate(['acknowledged' => ['required', 'accepted']]);
        $pending = $request->attributes->get('identity.pending');
        abort_unless($pending instanceof PendingAuthentication, 403);
        $correlationId = $request->attributes->get('correlation_id');
        $confirm->acknowledge(
            $pending,
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );

        $response = redirect()->route('home');
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }
}
