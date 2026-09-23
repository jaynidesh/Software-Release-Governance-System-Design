<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Authentication;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

final class RequestOtpRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        return ['email' => ['required', 'string', 'email', 'max:255']];
    }

    protected function prepareForValidation(): void
    {
        $this->merge(['email' => mb_strtolower(trim($this->string('email')->toString()))]);
    }
}
