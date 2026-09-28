<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Users;

use App\Models\User;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class UpdateUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->route('user') instanceof User && ($this->user()?->can('admin.users') ?? false);
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        $user = $this->route('user');

        return [
            'employee_number' => [
                'nullable', 'string', 'max:100',
                Rule::unique(User::class)->ignore($user instanceof User ? $user : null),
            ],
            'name' => ['required', 'string', 'max:255'],
            'email' => [
                'required', 'email:rfc', 'max:255',
                Rule::unique(User::class)->ignore($user instanceof User ? $user : null),
            ],
            'timezone' => ['required', 'timezone'],
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'employee_number' => trim($this->string('employee_number')->toString()) ?: null,
            'name' => trim($this->string('name')->toString()),
            'email' => mb_strtolower(trim($this->string('email')->toString())),
            'timezone' => trim($this->string('timezone')->toString()),
        ]);
    }
}
