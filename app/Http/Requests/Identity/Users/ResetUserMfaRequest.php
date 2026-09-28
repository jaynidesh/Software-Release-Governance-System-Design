<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Users;

use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;

final class ResetUserMfaRequest extends FormRequest
{
    public function authorize(): bool
    {
        $target = $this->route('user');
        $actor = $this->user();

        return $target instanceof User && $actor instanceof User
            && ! $actor->is($target) && $actor->can('admin.users');
    }

    /** @return array<string, never> */
    public function rules(): array
    {
        return [];
    }
}
