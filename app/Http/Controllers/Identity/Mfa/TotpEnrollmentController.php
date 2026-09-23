<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Mfa;

use App\Application\Identity\Mfa\BeginTotpEnrollment;
use App\Application\Identity\Mfa\ConfirmTotpEnrollment;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Mfa\ConfirmEnrollmentRequest;
use App\Models\PendingAuthentication;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

final class TotpEnrollmentController extends Controller
{
    public function create(Request $request, BeginTotpEnrollment $begin): Response
    {
        $pending = $this->pending($request);
        $enrollment = $begin->handle($pending);

        return response()->view('identity.mfa.enroll', $enrollment)
            ->header('Cache-Control', 'no-store, private');
    }

    public function store(ConfirmEnrollmentRequest $request, ConfirmTotpEnrollment $confirm): Response
    {
        $codes = $confirm->confirm($this->pending($request), $request->string('code')->toString());

        return response()->view('identity.mfa.recovery-codes', ['codes' => $codes, 'initial' => true])
            ->header('Cache-Control', 'no-store, private');
    }

    private function pending(Request $request): PendingAuthentication
    {
        $pending = $request->attributes->get('identity.pending');
        abort_unless($pending instanceof PendingAuthentication, 403);

        return $pending;
    }
}
