<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Users\UnlockUser;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Users\UnlockUserRequest;
use App\Models\User;
use Illuminate\Http\RedirectResponse;

final class UserUnlockController extends Controller
{
    public function store(
        UnlockUserRequest $request,
        User $user,
        UnlockUser $unlockUser,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $unlockUser->handle(
            $actor,
            $user,
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return back()->with('status', 'User unlocked.');
    }
}
