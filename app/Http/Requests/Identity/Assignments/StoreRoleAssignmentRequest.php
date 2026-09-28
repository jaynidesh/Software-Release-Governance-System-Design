<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Assignments;

use App\Domain\Identity\Enums\PermissionScope;
use App\Models\Application;
use App\Models\Role;
use App\Models\User;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;

final class StoreRoleAssignmentRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->route('user') instanceof User && ($this->user()?->can('admin.roles') ?? false);
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        return [
            'role' => ['required', 'string', Rule::exists(Role::class, 'public_id')->where('is_active', true)],
            'scope_type' => ['required', Rule::enum(PermissionScope::class)],
            'application' => [
                'nullable', 'string',
                Rule::exists(Application::class, 'public_id')->where('is_active', true),
            ],
            'starts_at' => ['nullable', 'date'],
            'ends_at' => ['nullable', 'date', 'after:starts_at'],
        ];
    }

    /** @return list<callable(Validator): void> */
    public function after(): array
    {
        return [function (Validator $validator): void {
            $scope = $this->string('scope_type')->toString();
            $hasApplication = $this->filled('application');

            if (($scope === PermissionScope::Application->value) !== $hasApplication) {
                $validator->errors()->add(
                    'application',
                    'Application scope requires one active application; global scope requires none.',
                );
            }
        }];
    }
}
