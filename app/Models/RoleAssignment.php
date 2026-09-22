<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\HasPublicUlid;
use App\Support\Exceptions\DomainRuleViolation;
use Database\Factories\RoleAssignmentFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable([
    'user_id', 'role_id', 'application_id', 'starts_at', 'ends_at', 'revoked_at',
    'assigned_by', 'revoked_by',
])]
class RoleAssignment extends Model
{
    /** @use HasFactory<RoleAssignmentFactory> */
    use HasFactory, HasPublicUlid;

    /**
     * Persist grant-starting transitions while holding the target application's row lock.
     *
     * @param  array<string, mixed>  $options
     */
    public function save(array $options = []): bool
    {
        if (! $this->beginsActiveScopedGrant()) {
            return parent::save($options);
        }

        return $this->getConnection()->transaction(function () use ($options): bool {
            $application = Application::query()
                ->whereKey($this->application_id)
                ->lockForUpdate()
                ->first();

            if (! $application?->is_active) {
                throw new DomainRuleViolation(
                    'inactive_application_assignment',
                    ['Activate the application before assigning a scoped role.'],
                );
            }

            return parent::save($options);
        });
    }

    protected function casts(): array
    {
        return [
            'starts_at' => 'datetime',
            'ends_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    private function beginsActiveScopedGrant(): bool
    {
        if ($this->application_id === null || $this->revoked_at !== null) {
            return false;
        }

        return ! $this->exists
            || $this->isDirty('application_id')
            || ($this->isDirty('revoked_at') && $this->getOriginal('revoked_at') !== null);
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /** @return BelongsTo<Role, $this> */
    public function role(): BelongsTo
    {
        return $this->belongsTo(Role::class);
    }

    /** @return BelongsTo<Application, $this> */
    public function application(): BelongsTo
    {
        return $this->belongsTo(Application::class);
    }

    /** @return BelongsTo<User, $this> */
    public function assigner(): BelongsTo
    {
        return $this->belongsTo(User::class, 'assigned_by');
    }

    /** @return BelongsTo<User, $this> */
    public function revoker(): BelongsTo
    {
        return $this->belongsTo(User::class, 'revoked_by');
    }
}
