<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Users;

use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;

final class ResendInvitationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->route('user') instanceof User && ($this->user()?->can('admin.users') ?? false);
    }

    /** @return array<string, never> */
    public function rules(): array
    {
        return [];
    }
}
