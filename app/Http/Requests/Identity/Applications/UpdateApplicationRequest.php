<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Applications;

use App\Models\Application;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class UpdateApplicationRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        $application = $this->route('application');

        return $application instanceof Application
            && ($this->user()?->can('update', $application) ?? false);
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        $application = $this->route('application');

        return [
            'name' => [
                'required',
                'string',
                'max:255',
                Rule::unique(Application::class, 'name')->ignore(
                    $application instanceof Application ? $application : null,
                ),
            ],
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge(['name' => trim($this->string('name')->toString())]);
    }
}
