<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Identity\Enums\MfaMethodType;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

#[Fillable([
    'user_id', 'type', 'secret', 'confirmed_at', 'rotated_at', 'disabled_at',
    'last_accepted_timestep',
])]
#[Hidden(['secret'])]
class UserMfaMethod extends Model
{
    protected function casts(): array
    {
        return [
            'type' => MfaMethodType::class,
            'secret' => 'encrypted',
            'confirmed_at' => 'datetime',
            'rotated_at' => 'datetime',
            'disabled_at' => 'datetime',
            'last_accepted_timestep' => 'integer',
        ];
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /** @return HasMany<UserRecoveryCode, $this> */
    public function recoveryCodes(): HasMany
    {
        return $this->hasMany(UserRecoveryCode::class);
    }
}
