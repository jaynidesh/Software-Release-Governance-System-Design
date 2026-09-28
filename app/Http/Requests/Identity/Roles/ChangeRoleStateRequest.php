<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Roles;

use App\Models\Role;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

final class ChangeRoleStateRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->route('role') instanceof Role && ($this->user()?->can('admin.roles') ?? false);
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        return ['is_active' => ['required', 'boolean']];
    }
}
