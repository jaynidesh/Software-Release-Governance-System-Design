<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Authentication;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

final class VerifyOtpRequest extends FormRequest
{
    protected $redirectRoute = 'identity.auth.otp.create';

    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        return [
            'code' => [
                'required',
                'string',
                'digits:'.(int) config('identity.otp.digits'),
            ],
        ];
    }

    /** @return array<string, string> */
    public function messages(): array
    {
        return [
            'code.required' => 'The code is invalid or expired.',
            'code.string' => 'The code is invalid or expired.',
            'code.digits' => 'The code is invalid or expired.',
        ];
    }
}
