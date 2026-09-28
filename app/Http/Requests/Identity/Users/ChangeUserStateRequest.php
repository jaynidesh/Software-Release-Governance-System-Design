<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Users;

use App\Domain\Identity\Enums\UserState;
use App\Models\User;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class ChangeUserStateRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->route('user') instanceof User && ($this->user()?->can('admin.users') ?? false);
    }

    /** @return array<string, ValidationRule|array<mixed>|string> */
    public function rules(): array
    {
        return ['state' => ['required', Rule::in([
            UserState::Active->value,
            UserState::Suspended->value,
            UserState::Deactivated->value,
        ])]];
    }
}
