<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\HasPublicUlid;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable([
    'session_id', 'user_id', 'started_at', 'last_seen_at', 'absolute_expires_at',
    'primary_authenticated_at', 'mfa_authenticated_at', 'reauthenticated_at',
    'user_session_version', 'revoked_at', 'ip_address', 'user_agent',
])]
#[Hidden(['session_id'])]
class AuthSession extends Model
{
    use HasPublicUlid;

    protected function casts(): array
    {
        return [
            'started_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'absolute_expires_at' => 'datetime',
            'primary_authenticated_at' => 'datetime',
            'mfa_authenticated_at' => 'datetime',
            'reauthenticated_at' => 'datetime',
            'user_session_version' => 'integer',
            'revoked_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
