<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Domain\Identity\Enums\UserState;
use App\Models\AuthSession;
use App\Models\User;
use Illuminate\Contracts\Session\Session;

final class CurrentAuthSessionValidator
{
    public function __construct(private readonly Session $session) {}

    public function current(
        User $user,
        bool $requiresMfa,
        bool $requiresFreshReauthentication,
    ): ?AuthSession {
        $state = $user->getAttribute('state');

        if (($state instanceof UserState ? $state : UserState::from((string) $state)) !== UserState::Active) {
            return null;
        }

        return AuthSession::query()
            ->where('session_id', $this->session->getId())
            ->where('user_id', $user->getKey())
            ->where('user_session_version', $user->session_version)
            ->whereNull('revoked_at')
            ->where('last_seen_at', '>', now()->subMinutes((int) config('identity.session.inactivity_minutes')))
            ->where('absolute_expires_at', '>', now())
            ->when($requiresMfa, static fn ($query) => $query->whereNotNull('mfa_authenticated_at'))
            ->when(
                $requiresFreshReauthentication,
                static fn ($query) => $query->where(
                    'reauthenticated_at',
                    '>=',
                    now()->subMinutes((int) config('identity.privileged_reauth_minutes')),
                ),
            )
            ->first();
    }

    public function hasFreshMfa(User $user): bool
    {
        return $this->current($user, true, true) !== null;
    }
}
