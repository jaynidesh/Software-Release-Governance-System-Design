<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Users\ResendInvitation;
use App\Application\Identity\Users\RevokeInvitation;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Users\ResendInvitationRequest;
use App\Models\User;
use Illuminate\Http\RedirectResponse;

final class InvitationController extends Controller
{
    public function store(
        ResendInvitationRequest $request,
        User $user,
        ResendInvitation $resendInvitation,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $resendInvitation->handle(
            $actor,
            $user,
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return back()->with('status', 'Invitation resent.');
    }

    public function destroy(
        ResendInvitationRequest $request,
        User $user,
        RevokeInvitation $revokeInvitation,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $revokeInvitation->handle(
            $actor,
            $user,
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return back()->with('status', 'Invitation revoked.');
    }
}
