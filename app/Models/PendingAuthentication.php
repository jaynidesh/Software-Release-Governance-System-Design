<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\Concerns\HasPublicUlid;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable([
    'user_id', 'auth_challenge_id', 'purpose', 'session_id_hmac', 'user_session_version',
    'expires_at', 'completed_at', 'invalidated_at', 'request_ip', 'user_agent', 'correlation_id',
])]
#[Hidden(['session_id_hmac'])]
class PendingAuthentication extends Model
{
    use HasPublicUlid;

    protected function casts(): array
    {
        return [
            'purpose' => AuthenticationPurpose::class,
            'user_session_version' => 'integer',
            'expires_at' => 'datetime',
            'completed_at' => 'datetime',
            'invalidated_at' => 'datetime',
        ];
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /** @return BelongsTo<AuthChallenge, $this> */
    public function challenge(): BelongsTo
    {
        return $this->belongsTo(AuthChallenge::class, 'auth_challenge_id');
    }
}
