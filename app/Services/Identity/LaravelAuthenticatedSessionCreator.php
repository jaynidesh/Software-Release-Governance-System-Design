<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Contracts\Identity\AuthenticatedSessionCreator;
use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\User;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use LogicException;

/** Interim Task 4 boundary; Task 5 decorates/replaces this with auth-session metadata persistence. */
final class LaravelAuthenticatedSessionCreator implements AuthenticatedSessionCreator
{
    public function __construct(
        private readonly AuthManager $auth,
        private readonly Session $session,
    ) {}

    public function create(User $user, AuthenticationPurpose $purpose, bool $mfaAuthenticated): void
    {
        $guard = $this->auth->guard();

        if (! $guard instanceof StatefulGuard) {
            throw new LogicException('The configured authentication guard must be stateful.');
        }

        $guard->login($user, false);
        $this->session->regenerate();
        $this->session->forget([
            'identity.pending_authentication',
            'identity.auth_challenge',
            'identity.auth_purpose',
        ]);
    }
}
