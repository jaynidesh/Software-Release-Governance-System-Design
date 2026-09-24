<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Mfa\RegenerateRecoveryCodes;
use App\Application\Identity\Mfa\RotateTotp;
use App\Http\Controllers\Controller;
use App\Models\AuthSession;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\View\View;

final class SecurityOverviewController extends Controller
{
    public function __invoke(Request $request): View
    {
        $user = $request->user();
        abort_unless($user instanceof User, 403);

        return view('identity.security.index', [
            'sessions' => $this->sessions($user),
            'currentSessionId' => $request->session()->getId(),
        ]);
    }

    public function regenerateRecoveryCodes(Request $request, RegenerateRecoveryCodes $regenerate): Response
    {
        $user = $request->user();
        abort_unless($user instanceof User, 403);
        $correlationId = $request->attributes->get('correlation_id');
        $codes = $regenerate->handle(
            $user,
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );

        return response()->view('identity.security.index', [
            'sessions' => $this->sessions($user),
            'currentSessionId' => $request->session()->getId(),
            'recoveryCodes' => $codes,
        ]);
    }

    public function rotateTotp(Request $request, RotateTotp $rotate): Response
    {
        $user = $request->user();
        abort_unless($user instanceof User, 403);
        $correlationId = $request->attributes->get('correlation_id');
        $rotation = $rotate->handle(
            $user,
            $request->ip(),
            $request->userAgent(),
            is_string($correlationId) ? $correlationId : null,
        );

        return response()->view('identity.security.index', [
            'sessions' => $this->sessions($user),
            'currentSessionId' => $request->session()->getId(),
            'totpRotation' => $rotation,
        ]);
    }

    /** @return Collection<int, AuthSession> */
    private function sessions(User $user): Collection
    {
        return $user->authSessions()
            ->whereNull('revoked_at')
            ->orderByDesc('last_seen_at')
            ->get();
    }
}
