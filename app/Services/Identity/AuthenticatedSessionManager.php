<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthSession;
use App\Models\User;
use App\Support\Exceptions\AuthenticatedSessionPersistenceException;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;
use Throwable;

final class AuthenticatedSessionManager
{
    private const ORPHAN_GRACE_SECONDS = 300;

    public function __construct(
        private readonly AuthManager $auth,
        private readonly Session $session,
        private readonly IdentityEventRecorder $events,
    ) {}

    public function authenticate(User $user, AuthenticationPurpose $purpose, bool $mfaAuthenticated): AuthSession
    {
        $guard = $this->guard();
        $oldSessionId = $this->session->getId();
        $newSessionId = null;

        try {
            $authSession = DB::transaction(function () use ($guard, $user, $purpose, $mfaAuthenticated, $oldSessionId, &$newSessionId): AuthSession {
                $guard->login($user, false);
                $this->session->regenerate();
                $newSessionId = $this->session->getId();
                $now = now();
                $authSession = AuthSession::query()->create([
                    'session_id' => $newSessionId,
                    'user_id' => $user->getKey(),
                    'started_at' => $now,
                    'last_seen_at' => $now,
                    'absolute_expires_at' => $now->copy()->addMinutes((int) config('identity.session.absolute_minutes')),
                    'primary_authenticated_at' => $now,
                    'mfa_authenticated_at' => $mfaAuthenticated ? $now : null,
                    'reauthenticated_at' => $mfaAuthenticated ? $now : null,
                    'user_session_version' => $user->session_version,
                    'ip_address' => request()->ip(),
                    'user_agent' => $this->boundedUserAgent(request()->userAgent()),
                ]);
                $this->events->security(
                    'identity.session.created',
                    $user,
                    $user,
                    ['purpose' => $purpose->value],
                    request()->ip(),
                    request()->userAgent(),
                    $this->correlationId(),
                );
                DB::table('sessions')->where('id', $oldSessionId)->delete();
                $this->forgetAuthenticationState();

                return $authSession;
            }, 3);

            if (DB::transactionLevel() > 0) {
                DB::afterRollBack(function () use ($guard): void {
                    $guard->logout();
                    $this->session->invalidate();
                    $this->session->regenerateToken();
                });
            }

            return $authSession;
        } catch (Throwable) {
            $this->discardFailedAuthentication($newSessionId);

            $this->rollbackFailedAuthentication($guard);
            $this->schedulePersistenceFailure($user);

            throw new AuthenticatedSessionPersistenceException;
        }
    }

    public function rekey(User $user, bool $completeReauthentication): AuthSession
    {
        $oldSessionId = $this->session->getId();

        try {
            $authSession = DB::transaction(function () use ($user, $oldSessionId, $completeReauthentication): AuthSession {
                $authSession = AuthSession::query()
                    ->where('session_id', $oldSessionId)
                    ->where('user_id', $user->getKey())
                    ->lockForUpdate()
                    ->firstOrFail();
                $this->session->regenerate();
                $now = now();
                $attributes = [
                    'session_id' => $this->session->getId(),
                    'last_seen_at' => $now,
                    'ip_address' => request()->ip(),
                    'user_agent' => $this->boundedUserAgent(request()->userAgent()),
                ];

                if ($completeReauthentication) {
                    $attributes['mfa_authenticated_at'] = $now;
                    $attributes['reauthenticated_at'] = $now;
                }

                $authSession->forceFill($attributes)->save();
                DB::table('sessions')->where('id', $oldSessionId)->delete();

                if ($completeReauthentication) {
                    $this->events->security(
                        'identity.reauthentication.succeeded',
                        $user,
                        $user,
                        [],
                        request()->ip(),
                        request()->userAgent(),
                        $this->correlationId(),
                    );
                    $this->forgetAuthenticationState();
                }

                return $authSession;
            }, 3);

            if (DB::transactionLevel() > 0) {
                DB::afterRollBack(fn () => $this->session->setId($oldSessionId));
            }

            return $authSession;
        } catch (Throwable) {
            $this->session->setId($oldSessionId);
            $this->schedulePersistenceFailure($user);

            throw new AuthenticatedSessionPersistenceException;
        }
    }

    public function invalidateCurrent(User $user): void
    {
        $this->terminateCurrent($user, 'identity.session.invalidated');
    }

    public function logoutCurrent(User $user): void
    {
        $this->terminateCurrent($user, 'identity.session.logged_out');
    }

    private function terminateCurrent(User $user, string $eventCode): void
    {
        $sessionId = $this->session->getId();

        DB::transaction(function () use ($user, $sessionId, $eventCode): void {
            DB::table('sessions')->where('id', $sessionId)->delete();
            AuthSession::query()->where('session_id', $sessionId)->delete();
            $this->events->security(
                $eventCode,
                $user,
                $user,
                [],
                request()->ip(),
                request()->userAgent(),
                $this->correlationId(),
            );
        }, 3);

        $this->logoutBrowser();
    }

    public function logoutBrowser(): void
    {
        $this->guard()->logout();
        $this->session->invalidate();
        $this->session->regenerateToken();
    }

    /** @return array{metadata: int, payloads: int} */
    public function purgeOrphans(int $chunkSize = 500): array
    {
        $metadataCutoff = now()->subSeconds(self::ORPHAN_GRACE_SECONDS);
        $payloadCutoff = $metadataCutoff->timestamp;
        $metadata = 0;

        do {
            $deleted = DB::transaction(function () use ($chunkSize, $metadataCutoff): int {
                $ids = AuthSession::query()
                    ->where('updated_at', '<=', $metadataCutoff)
                    ->whereNotExists(static function ($query): void {
                        $query->selectRaw('1')
                            ->from('sessions')
                            ->whereColumn('sessions.id', 'auth_sessions.session_id');
                    })
                    ->orderBy('id')
                    ->limit($chunkSize)
                    ->lockForUpdate()
                    ->pluck('id');

                return $ids->isEmpty() ? 0 : AuthSession::query()
                    ->whereKey($ids)
                    ->where('updated_at', '<=', $metadataCutoff)
                    ->whereNotExists(static function ($query): void {
                        $query->selectRaw('1')
                            ->from('sessions')
                            ->whereColumn('sessions.id', 'auth_sessions.session_id');
                    })
                    ->delete();
            }, 3);
            $metadata += $deleted;
        } while ($deleted === $chunkSize);

        $payloads = 0;

        do {
            $deleted = DB::transaction(function () use ($chunkSize, $payloadCutoff): int {
                $ids = DB::table('sessions')
                    ->whereNotNull('user_id')
                    ->where('last_activity', '<=', $payloadCutoff)
                    ->whereNotExists(static function ($query): void {
                        $query->selectRaw('1')
                            ->from('auth_sessions')
                            ->whereColumn('auth_sessions.session_id', 'sessions.id');
                    })
                    ->orderBy('id')
                    ->limit($chunkSize)
                    ->lockForUpdate()
                    ->pluck('id');

                return $ids->isEmpty() ? 0 : DB::table('sessions')
                    ->whereIn('id', $ids)
                    ->whereNotNull('user_id')
                    ->where('last_activity', '<=', $payloadCutoff)
                    ->whereNotExists(static function ($query): void {
                        $query->selectRaw('1')
                            ->from('auth_sessions')
                            ->whereColumn('auth_sessions.session_id', 'sessions.id');
                    })
                    ->delete();
            }, 3);
            $payloads += $deleted;
        } while ($deleted === $chunkSize);

        return ['metadata' => $metadata, 'payloads' => $payloads];
    }

    private function guard(): StatefulGuard
    {
        $guard = $this->auth->guard();

        if (! $guard instanceof StatefulGuard) {
            throw new LogicException('The configured authentication guard must be stateful.');
        }

        return $guard;
    }

    private function forgetAuthenticationState(): void
    {
        $this->session->forget([
            'identity.pending_authentication',
            'identity.auth_challenge',
            'identity.auth_purpose',
            'identity.otp_resend_available_at',
        ]);
    }

    private function discardFailedAuthentication(?string $sessionId): void
    {
        if ($sessionId === null) {
            return;
        }

        try {
            AuthSession::query()->where('session_id', $sessionId)->delete();
            DB::table('sessions')->where('id', $sessionId)->delete();
        } catch (Throwable) {
            // Browser authentication rollback and the sanitized failure remain mandatory during a database outage.
        }
    }

    private function rollbackFailedAuthentication(StatefulGuard $guard): void
    {
        try {
            $guard->logout();
        } catch (Throwable) {
            // Continue clearing the browser session even when the backing store is unavailable.
        }

        try {
            $this->session->invalidate();
        } catch (Throwable) {
            $this->session->flush();
            $this->session->setId(Str::random(40));
        }

        $this->session->regenerateToken();
    }

    private function boundedUserAgent(?string $userAgent): ?string
    {
        return $userAgent === null ? null : mb_substr($userAgent, 0, 500);
    }

    private function recordPersistenceFailure(User $user): void
    {
        try {
            $this->events->security(
                'identity.session.persistence_failed',
                null,
                $user,
                [],
                request()->ip(),
                request()->userAgent(),
                $this->correlationId(),
            );
        } catch (Throwable) {
            // The original persistence failure remains intentionally unreported to avoid leaking session identifiers.
        }
    }

    private function schedulePersistenceFailure(User $user): void
    {
        if (DB::transactionLevel() > 0) {
            DB::afterRollBack(fn () => $this->recordPersistenceFailure($user));

            return;
        }

        $this->recordPersistenceFailure($user);
    }

    private function correlationId(): ?string
    {
        $correlationId = request()->attributes->get('correlation_id');

        return is_string($correlationId) ? $correlationId : null;
    }
}
