<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Mfa;

use Illuminate\Foundation\Http\FormRequest;

final class RegenerateRecoveryCodesRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user() !== null;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return ['acknowledged' => ['required', 'accepted']];
    }
}
