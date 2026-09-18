<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Identity\Enums\PermissionScope;
use Database\Factories\PermissionFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

#[Fillable(['code', 'description', 'scope_type'])]
class Permission extends Model
{
    public $timestamps = false;

    /** @use HasFactory<PermissionFactory> */
    use HasFactory;

    protected function casts(): array
    {
        return ['scope_type' => PermissionScope::class];
    }

    /** @return Attribute<never, string> */
    protected function code(): Attribute
    {
        return Attribute::set(static fn (string $value): string => mb_strtolower(trim($value)));
    }

    /** @return BelongsToMany<Role, $this> */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class, 'role_permissions');
    }
}
