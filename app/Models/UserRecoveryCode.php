<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

#[Fillable(['user_mfa_method_id', 'code_hmac', 'used_at'])]
#[Hidden(['code_hmac'])]
class UserRecoveryCode extends Model
{
    public $timestamps = false;

    protected function casts(): array
    {
        return ['used_at' => 'datetime', 'created_at' => 'datetime'];
    }

    /** @return BelongsTo<UserMfaMethod, $this> */
    public function mfaMethod(): BelongsTo
    {
        return $this->belongsTo(UserMfaMethod::class, 'user_mfa_method_id');
    }
}
