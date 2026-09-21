<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Applications;

use App\Models\Application;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class StoreApplicationRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()?->can('create', Application::class) ?? false;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'code' => [
                'required',
                'string',
                'max:100',
                'regex:/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/',
                Rule::unique(Application::class, 'code'),
            ],
            'name' => ['required', 'string', 'max:255', Rule::unique(Application::class, 'name')],
        ];
    }

    protected function prepareForValidation(): void
    {
        $this->merge([
            'code' => mb_strtolower(trim($this->string('code')->toString())),
            'name' => trim($this->string('name')->toString()),
        ]);
    }
}
