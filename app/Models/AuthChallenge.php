<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\Concerns\HasPublicUlid;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

#[Fillable([
    'user_id', 'purpose', 'code_hmac', 'expires_at', 'failed_attempts', 'delivered_at',
    'consumed_at', 'invalidated_at', 'request_ip', 'user_agent', 'correlation_id',
])]
#[Hidden(['code_hmac'])]
class AuthChallenge extends Model
{
    use HasPublicUlid;

    protected function casts(): array
    {
        return [
            'purpose' => AuthenticationPurpose::class,
            'expires_at' => 'datetime',
            'failed_attempts' => 'integer',
            'delivered_at' => 'datetime',
            'consumed_at' => 'datetime',
            'invalidated_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /** @return HasMany<PendingAuthentication, $this> */
    public function pendingAuthentications(): HasMany
    {
        return $this->hasMany(PendingAuthentication::class);
    }
}
