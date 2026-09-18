<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Identity\Enums\UserState;
use App\Models\Concerns\HasPublicUlid;
use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

#[Fillable([
    'employee_number', 'name', 'email', 'state', 'timezone', 'email_verified_at',
    'invited_at', 'invitation_expires_at', 'activated_at', 'last_login_at',
    'failed_auth_attempts', 'failed_auth_window_started_at', 'locked_until', 'session_version',
])]
class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, HasPublicUlid, Notifiable, SoftDeletes;

    /** @var array<string, mixed> */
    protected $attributes = [
        'state' => UserState::Deactivated->value,
        'timezone' => 'UTC',
        'failed_auth_attempts' => 0,
        'session_version' => 1,
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'state' => UserState::class,
            'invited_at' => 'datetime',
            'invitation_expires_at' => 'datetime',
            'activated_at' => 'datetime',
            'last_login_at' => 'datetime',
            'failed_auth_window_started_at' => 'datetime',
            'locked_until' => 'datetime',
            'failed_auth_attempts' => 'integer',
            'session_version' => 'integer',
        ];
    }

    /** @return Attribute<never, string> */
    protected function email(): Attribute
    {
        return Attribute::set(static fn (string $value): string => mb_strtolower(trim($value)));
    }

    /** @return HasMany<RoleAssignment, $this> */
    public function roleAssignments(): HasMany
    {
        return $this->hasMany(RoleAssignment::class);
    }

    /** @return HasMany<AuthChallenge, $this> */
    public function authChallenges(): HasMany
    {
        return $this->hasMany(AuthChallenge::class);
    }

    /** @return HasMany<PendingAuthentication, $this> */
    public function pendingAuthentications(): HasMany
    {
        return $this->hasMany(PendingAuthentication::class);
    }

    /** @return HasMany<UserMfaMethod, $this> */
    public function mfaMethods(): HasMany
    {
        return $this->hasMany(UserMfaMethod::class);
    }

    /** @return HasMany<AuthSession, $this> */
    public function authSessions(): HasMany
    {
        return $this->hasMany(AuthSession::class);
    }
}
