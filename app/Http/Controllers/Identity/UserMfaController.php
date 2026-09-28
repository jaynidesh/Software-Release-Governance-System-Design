<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Mfa\ResetUserMfa;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Users\ResetUserMfaRequest;
use App\Models\User;
use Illuminate\Http\RedirectResponse;

final class UserMfaController extends Controller
{
    public function destroy(
        ResetUserMfaRequest $request,
        User $user,
        ResetUserMfa $resetUserMfa,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $resetUserMfa->handle(
            $actor,
            $user,
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return back()->with('status', 'Multi-factor authentication reset.');
    }
}
