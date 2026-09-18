<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\Concerns\AppendOnly;
use App\Models\Concerns\HasPublicUlid;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable([
    'user_id', 'identifier_hmac', 'purpose', 'result_code', 'ip_address', 'user_agent',
    'correlation_id', 'occurred_at',
])]
#[Hidden(['identifier_hmac'])]
class LoginEvent extends Model
{
    use AppendOnly, HasPublicUlid;

    public $timestamps = false;

    protected function casts(): array
    {
        return ['purpose' => AuthenticationPurpose::class, 'occurred_at' => 'datetime'];
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
