<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Users\ChangeUserState;
use App\Domain\Identity\Enums\UserState;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Users\ChangeUserStateRequest;
use App\Models\User;
use Illuminate\Http\RedirectResponse;

final class UserStateController extends Controller
{
    public function __invoke(
        ChangeUserStateRequest $request,
        User $user,
        ChangeUserState $changeUserState,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $changeUserState->handle(
            $actor,
            $user,
            UserState::from($request->string('state')->toString()),
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return redirect()->route('admin.users.show', $user)->with('status', 'User state updated.');
    }
}
