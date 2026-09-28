<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Roles;

use App\Models\Role;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class StoreRoleRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->can('admin.roles') ?? false;
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        return [
            'code' => [
                'required', 'string', 'max:100',
                'regex:/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/', Rule::unique(Role::class),
            ],
            'name' => ['required', 'string', 'max:255', Rule::unique(Role::class)],
            'description' => ['nullable', 'string', 'max:2000'],
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'code' => mb_strtolower(trim($this->string('code')->toString())),
            'name' => trim($this->string('name')->toString()),
            'description' => trim($this->string('description')->toString()) ?: null,
        ]);
    }
}
