<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Assignments\AssignRole;
use App\Application\Identity\Assignments\RevokeRoleAssignment;
use App\Domain\Identity\Enums\PermissionScope;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Assignments\RevokeRoleAssignmentRequest;
use App\Http\Requests\Identity\Assignments\StoreRoleAssignmentRequest;
use App\Models\Application;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use Carbon\CarbonImmutable;
use Illuminate\Http\RedirectResponse;

final class RoleAssignmentController extends Controller
{
    public function store(
        StoreRoleAssignmentRequest $request,
        User $user,
        AssignRole $assignRole,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $application = $request->string('scope_type')->toString() === PermissionScope::Application->value
            ? Application::query()->where('public_id', $request->string('application')->toString())->firstOrFail()
            : null;
        $assignRole->handle(
            $actor,
            $user,
            Role::query()->where('public_id', $request->string('role')->toString())->firstOrFail(),
            $application,
            $request->filled('starts_at') ? CarbonImmutable::parse($request->string('starts_at')->toString()) : now(),
            $request->filled('ends_at') ? CarbonImmutable::parse($request->string('ends_at')->toString()) : null,
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return back()->with('status', 'Role assigned.');
    }

    public function destroy(
        RevokeRoleAssignmentRequest $request,
        User $user,
        RoleAssignment $roleAssignment,
        RevokeRoleAssignment $revokeRoleAssignment,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $revokeRoleAssignment->handle(
            $actor,
            $roleAssignment,
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return back()->with('status', 'Role assignment revoked.');
    }
}
