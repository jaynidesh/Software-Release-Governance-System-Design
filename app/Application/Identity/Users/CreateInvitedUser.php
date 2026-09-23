<?php

declare(strict_types=1);

namespace App\Application\Identity\Users;

use App\Contracts\Identity\AuthorizationService;
use App\Domain\Identity\Enums\UserState;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Services\Identity\IdentityEventRecorder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

final class CreateInvitedUser
{
    public function __construct(
        private readonly AuthorizationService $authorization,
        private readonly IdentityEventRecorder $events,
    ) {}

    /** @param array{employee_number?: string|null, name: string, email: string, timezone: string} $attributes */
    public function handle(
        User $actor,
        array $attributes,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): User {
        return DB::transaction(function () use (
            $actor,
            $attributes,
            $ipAddress,
            $userAgent,
            $correlationId,
        ): User {
            $this->authorize($actor);
            $user = User::query()->create([
                'employee_number' => $attributes['employee_number'] ?? null,
                'name' => trim($attributes['name']),
                'email' => $attributes['email'],
                'state' => UserState::Invited,
                'timezone' => $attributes['timezone'],
                'email_verified_at' => null,
                'invited_at' => now(),
                'invitation_expires_at' => now()->addDays((int) config('identity.invitation_ttl_days')),
                'activated_at' => null,
            ]);
            $this->events->security(
                'identity.invitation.created',
                $actor,
                $user,
                [],
                $ipAddress,
                $userAgent,
                $correlationId,
            );
            $user->notify(new ActivationInvitationNotification);

            return $user;
        }, 3);
    }

    private function authorize(User $actor): void
    {
        if (! $this->authorization->allows($actor, 'admin.users', null, true)) {
            throw new AuthorizationException;
        }
    }
}
