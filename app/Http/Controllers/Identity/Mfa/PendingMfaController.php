<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Mfa;

use App\Application\Identity\Mfa\VerifyPendingMfa;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Mfa\VerifyMfaRequest;
use App\Models\PendingAuthentication;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;

final class PendingMfaController extends Controller
{
    public function create(): Response
    {
        return response()->view('identity.mfa.verify')
            ->header('Cache-Control', 'no-store, private');
    }

    public function store(VerifyMfaRequest $request, VerifyPendingMfa $verify): RedirectResponse
    {
        $pending = $request->attributes->get('identity.pending');
        abort_unless($pending instanceof PendingAuthentication, 403);
        $correlationId = $request->attributes->get('correlation_id');
        try {
            $result = $verify->handle(
                $pending,
                $request->string('code')->toString(),
                $request->ip(),
                $request->userAgent(),
                is_string($correlationId) ? $correlationId : null,
            );
        } catch (ValidationException) {
            $response = redirect()->route('identity.mfa.verify.create')
                ->withErrors(['code' => 'The authentication code is invalid or expired.']);
            $response->headers->set('Cache-Control', 'no-store, private');

            return $response;
        }
        $response = redirect()->route('home');

        if ($result['used_recovery'] && $result['remaining_recovery'] <= 2) {
            $response->with('warning', sprintf(
                'You have %d recovery codes remaining. Generate a new set now.',
                $result['remaining_recovery'],
            ));
        }

        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }
}
