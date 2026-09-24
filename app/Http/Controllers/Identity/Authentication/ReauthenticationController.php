<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Authentication;

use App\Application\Identity\Authentication\VerifyEmailOtp;
use App\Application\Identity\Reauthentication\BeginReauthentication;
use App\Application\Identity\Reauthentication\CompleteReauthentication;
use App\Http\Controllers\Controller;
use App\Models\PendingAuthentication;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;

final class ReauthenticationController extends Controller
{
    public function show(Request $request): Response
    {
        return response()->view('identity.auth.reauthenticate', [
            'stage' => $request->session()->has('identity.auth_challenge') ? 'otp' : 'start',
        ]);
    }

    public function store(Request $request, BeginReauthentication $begin): RedirectResponse
    {
        $validated = $request->validate(['return_route' => ['nullable', 'string', 'max:150']]);
        $user = $request->user();
        abort_unless($user instanceof User, 403);
        $correlationId = $request->attributes->get('correlation_id');
        $begin->handle(
            $user,
            is_string($validated['return_route'] ?? null) ? $validated['return_route'] : null,
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );

        return redirect()->route('identity.reauthentication.show')
            ->with('status', 'A verification code has been sent.');
    }

    public function verify(Request $request, VerifyEmailOtp $verify): RedirectResponse
    {
        $request->validate(['code' => ['required', 'string', 'max:32']]);
        $correlationId = $request->attributes->get('correlation_id');

        try {
            $completed = $verify->handle(
                $request->string('code')->toString(),
                $request->ip(),
                $request->userAgent(),
                is_string($correlationId) ? $correlationId : null,
            );
        } catch (ValidationException) {
            return redirect()->route('identity.reauthentication.show')
                ->withErrors(['code' => 'The code is invalid or expired.']);
        }

        abort_unless($completed->pendingAuthentication instanceof PendingAuthentication, 403);

        return redirect()->route('identity.reauthentication.mfa.show');
    }

    public function mfa(): Response
    {
        return response()->view('identity.auth.reauthenticate', ['stage' => 'mfa']);
    }

    public function complete(Request $request, CompleteReauthentication $complete): RedirectResponse
    {
        $request->validate(['code' => ['required', 'string', 'max:32']]);
        $pending = $request->attributes->get('identity.pending');
        abort_unless($pending instanceof PendingAuthentication, 403);
        $correlationId = $request->attributes->get('correlation_id');

        try {
            $route = $complete->handle(
                $pending,
                $request->string('code')->toString(),
                $request->ip(),
                $request->userAgent(),
                is_string($correlationId) ? $correlationId : null,
            );
        } catch (ValidationException) {
            return redirect()->route('identity.reauthentication.mfa.show')
                ->withErrors(['code' => 'The authentication code is invalid or expired.']);
        }

        return redirect()->route($route);
    }
}
