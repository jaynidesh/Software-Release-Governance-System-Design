<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Authentication;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\Identity\AuthenticatedSessionManager;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class LogoutController extends Controller
{
    public function __invoke(Request $request, AuthenticatedSessionManager $sessions): RedirectResponse
    {
        $user = $request->user();
        abort_unless($user instanceof User, 403);
        $sessions->logoutCurrent($user);

        return redirect()->route('login');
    }
}
