<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Roles;

use App\Models\Permission;
use App\Models\Role;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class SyncRolePermissionsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->route('role') instanceof Role && ($this->user()?->can('admin.roles') ?? false);
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        return [
            'permissions' => ['present', 'array'],
            'permissions.*' => ['required', 'string', 'distinct', Rule::exists(Permission::class, 'code')],
        ];
    }
}
