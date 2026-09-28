<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Users;

use App\Domain\Identity\Enums\PermissionScope;
use App\Models\Application;
use App\Models\Role;
use App\Models\User;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;

final class StoreUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        $user = $this->user();

        return $user instanceof User
            && $user->can('admin.users')
            && ($this->input('assignments', []) === [] || $user->can('admin.roles'));
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        return [
            'employee_number' => ['nullable', 'string', 'max:100', Rule::unique(User::class)],
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email:rfc', 'max:255', Rule::unique(User::class)],
            'timezone' => ['required', 'timezone'],
            'assignments' => ['sometimes', 'array'],
            'assignments.*.role' => ['required', 'string', Rule::exists(Role::class, 'public_id')->where('is_active', true)],
            'assignments.*.scope_type' => ['required', Rule::enum(PermissionScope::class)],
            'assignments.*.application' => [
                'nullable',
                'string',
                Rule::exists(Application::class, 'public_id')->where('is_active', true),
            ],
            'assignments.*.starts_at' => ['nullable', 'date'],
            'assignments.*.ends_at' => ['nullable', 'date', 'after:assignments.*.starts_at'],
        ];
    }

    /** @return array<int, callable(Validator): void> */
    public function after(): array
    {
        return [function (Validator $validator): void {
            foreach ($this->array('assignments') as $index => $assignment) {
                if (! is_array($assignment)) {
                    continue;
                }

                $scope = $assignment['scope_type'] ?? null;
                $application = $assignment['application'] ?? null;
                $hasApplication = is_string($application) && trim($application) !== '';

                if (($scope === PermissionScope::Application->value) !== $hasApplication) {
                    $validator->errors()->add(
                        "assignments.{$index}.application",
                        'An active application is required only for application-scoped assignments.',
                    );
                }
            }
        }];
    }

    protected function prepareForValidation(): void
    {
        $assignments = [];

        foreach ($this->array('assignments') as $assignment) {
            if (is_array($assignment)
                && is_string($assignment['role'] ?? null)
                && trim($assignment['role']) !== '') {
                $assignments[] = $assignment;
            }
        }
        $this->merge([
            'employee_number' => trim($this->string('employee_number')->toString()) ?: null,
            'name' => trim($this->string('name')->toString()),
            'email' => mb_strtolower(trim($this->string('email')->toString())),
            'timezone' => trim($this->string('timezone')->toString()),
            'assignments' => $assignments,
        ]);
    }
}
