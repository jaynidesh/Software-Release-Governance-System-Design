<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Authentication;

use App\Application\Identity\Authentication\BeginEmailOtp;
use App\Application\Identity\Authentication\VerifyEmailOtp;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Authentication\RequestOtpRequest;
use App\Http\Requests\Identity\Authentication\VerifyOtpRequest;
use App\Models\AuthChallenge;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;

final class OtpChallengeController extends Controller
{
    public function create(Request $request): Response
    {
        $challengeReference = $request->session()->get('identity.auth_challenge');
        $challenge = is_string($challengeReference)
            ? AuthChallenge::query()
                ->select(['id', 'created_at'])
                ->where('public_id', $challengeReference)
                ->first()
            : null;
        $resendAvailableAt = $challenge?->created_at?->copy()->addSeconds(
            (int) config('identity.otp.resend_seconds'),
        );

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
        $resent = $beginEmailOtp->resend(
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );

        $response = redirect()->route('identity.auth.otp.create')->with(
            'status',
            $resent
                ? 'If the account remains eligible, a new code was sent.'
                : 'A new code is available when the resend countdown reaches zero.',
        );
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }
}
