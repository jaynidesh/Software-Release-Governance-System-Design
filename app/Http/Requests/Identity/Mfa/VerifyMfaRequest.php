<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Mfa;

use Illuminate\Foundation\Http\FormRequest;

final class VerifyMfaRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->attributes->has('identity.pending');
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return ['code' => ['required', 'string', 'max:32']];
    }
}
