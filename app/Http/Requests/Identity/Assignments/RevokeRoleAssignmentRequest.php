<?php

declare(strict_types=1);

namespace App\Http\Requests\Identity\Assignments;

use App\Models\RoleAssignment;
use App\Models\User;
use Illuminate\Foundation\Http\FormRequest;

final class RevokeRoleAssignmentRequest extends FormRequest
{
    public function authorize(): bool
    {
        $target = $this->route('user');
        $assignment = $this->route('roleAssignment');

        return $target instanceof User
            && $assignment instanceof RoleAssignment
            && $assignment->user_id === $target->id
            && ($this->user()?->can('admin.roles') ?? false);
    }

    /** @return array<string, never> */
    public function rules(): array
    {
        return [];
    }
}
