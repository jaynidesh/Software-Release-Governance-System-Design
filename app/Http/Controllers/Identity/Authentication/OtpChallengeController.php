<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Authentication;

use App\Application\Identity\Authentication\BeginEmailOtp;
use App\Application\Identity\Authentication\VerifyEmailOtp;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Authentication\RequestOtpRequest;
use App\Http\Requests\Identity\Authentication\VerifyOtpRequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;

final class OtpChallengeController extends Controller
{
    public function create(): Response
    {
        return response()->view('identity.auth.verify-otp')
            ->header('Cache-Control', 'no-store, private');
    }

    public function store(RequestOtpRequest $request, BeginEmailOtp $beginEmailOtp): RedirectResponse
    {
        $correlationId = $request->attributes->get('correlation_id');
        $beginEmailOtp->handle(
            $request->string('email')->toString(),
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );

        $response = redirect()->route('identity.auth.otp.create')
            ->with('status', 'If the account is eligible, a sign-in code will be sent.');
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }

    public function update(VerifyOtpRequest $request, VerifyEmailOtp $verifyEmailOtp): RedirectResponse
    {
        $correlationId = $request->attributes->get('correlation_id');

        try {
            $completed = $verifyEmailOtp->handle(
                $request->string('code')->toString(),
                $request->ip(),
                $request->userAgent(),
                is_string($correlationId) ? $correlationId : null,
            );
        } catch (ValidationException) {
            $response = redirect()->route('identity.auth.otp.create')
                ->withErrors(['code' => 'The code is invalid or expired.']);
            $response->headers->set('Cache-Control', 'no-store, private');

            return $response;
        }

        $response = $completed->requiresAdditionalProof()
            ? redirect()->route('login')->with('status', 'Additional authentication is required.')
            : redirect()->route('home');
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }
}
