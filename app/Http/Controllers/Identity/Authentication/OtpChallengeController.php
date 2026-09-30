<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Authentication;

use App\Application\Identity\Authentication\BeginEmailOtp;
use App\Application\Identity\Authentication\VerifyEmailOtp;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Authentication\RequestOtpRequest;
use App\Http\Requests\Identity\Authentication\VerifyOtpRequest;
use Carbon\CarbonImmutable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;

final class OtpChallengeController extends Controller
{
    public function create(Request $request): Response
    {
        $availableAt = $request->session()->get('identity.otp_resend_available_at');
        $resendAvailableAt = is_int($availableAt)
            ? CarbonImmutable::createFromTimestampMs($availableAt)
            : now()->toImmutable()->addSeconds((int) config('identity.otp.resend_seconds'));

        $request->session()->put('identity.otp_resend_available_at', $resendAvailableAt->getTimestampMs());

        return response()->view('identity.auth.verify-otp', [
            'resendAvailableAt' => $resendAvailableAt,
        ])
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
            ? redirect()->route($completed->user->mfaMethods()->whereNotNull('confirmed_at')->whereNull('disabled_at')->exists()
                ? 'identity.mfa.verify.create'
                : 'identity.mfa.enroll.create')
            : redirect()->route('home');
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }

    public function resend(Request $request, BeginEmailOtp $beginEmailOtp): RedirectResponse
    {
        $correlationId = $request->attributes->get('correlation_id');
        $beginEmailOtp->resend(
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );

        $response = redirect()->route('identity.auth.otp.create')
            ->with('status', 'If the account remains eligible, a new code may have been sent.');
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }
}
