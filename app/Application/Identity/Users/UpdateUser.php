<?php

declare(strict_types=1);

namespace App\Application\Identity\Users;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Services\Identity\EffectiveAdministratorGuard;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\IdentityMutationBoundary;
use App\Services\Identity\PrivilegeChangeInvalidator;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class UpdateUser
{
    public function __construct(private readonly IdentityMutationBoundary $mutationBoundary,
        private readonly AuthorizationService $authorization,
        private readonly EffectiveAdministratorGuard $administrators,
        private readonly PrivilegeChangeInvalidator $invalidator,
        private readonly IdentityEventRecorder $events,
    ) {}

    /** @param array{employee_number?: string|null, name: string, email: string, timezone: string} $attributes */
    public function handle(
        User $actor,
        User $target,
        array $attributes,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): User {
        return $this->mutationBoundary->run(function () use ($actor, $target, $attributes, $ipAddress, $userAgent, $correlationId): User {
            return DB::transaction(function () use (
                $actor,
                $target,
                $attributes,
                $ipAddress,
                $userAgent,
                $correlationId,
            ): User {
                $this->administrators->lockMutex();
                $users = User::query()
                    ->whereKey([(int) $actor->getKey(), (int) $target->getKey()])
                    ->orderBy('id')
                    ->lockForUpdate()
                    ->get()
                    ->keyBy('id');
                $lockedActor = $users->get($actor->getKey());
                $lockedTarget = $users->get($target->getKey());

                if (! $lockedActor instanceof User || ! $lockedTarget instanceof User
                    || ! $this->authorization->allows($lockedActor, 'admin.users', null, true)) {
                    throw new AuthorizationException;
                }

                $normalizedEmail = mb_strtolower(trim($attributes['email']));
                $emailChanged = $normalizedEmail !== (string) $lockedTarget->getRawOriginal('email');
                $lockedTarget->forceFill([
                    'employee_number' => isset($attributes['employee_number'])
                        ? trim((string) $attributes['employee_number']) ?: null
                        : null,
                    'name' => trim($attributes['name']),
                    'email' => $normalizedEmail,
                    'timezone' => $attributes['timezone'],
                ]);

                if ($emailChanged) {
                    $lockedTarget->forceFill([
                        'state' => UserState::Invited,
                        'email_verified_at' => null,
                        'activated_at' => null,
                        'invited_at' => now(),
                        'invitation_expires_at' => now()->addDays((int) config('identity.invitation_ttl_days')),
                    ]);
                }

                $lockedTarget->save();

                if ($emailChanged) {
                    $this->administrators->assertExists(
                        $lockedActor,
                        $lockedTarget,
                        $ipAddress,
                        $userAgent,
                        $correlationId,
                    );
                    $this->invalidator->invalidate($lockedTarget);
                    $this->events->security(
                        'identity.user.email_changed',
                        $lockedActor,
                        $lockedTarget,
                        [],
                        $ipAddress,
                        $userAgent,
                        $correlationId,
                    );
                    DB::afterCommit(static fn () => $lockedTarget->notify(new ActivationInvitationNotification));
                } else {
                    $this->events->security(
                        'identity.user.updated',
                        $lockedActor,
                        $lockedTarget,
                        [],
                        $ipAddress,
                        $userAgent,
                        $correlationId,
                    );
                }

                return $lockedTarget;
            }, 3);
        }, $actor, self::class, $ipAddress, $userAgent, $correlationId);
    }
}
