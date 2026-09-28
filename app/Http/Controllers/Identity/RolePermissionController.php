<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Roles\SyncRolePermissions;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Roles\SyncRolePermissionsRequest;
use App\Models\Permission;
use App\Models\Role;
use App\Models\User;
use Illuminate\Http\RedirectResponse;

final class RolePermissionController extends Controller
{
    public function update(
        SyncRolePermissionsRequest $request,
        Role $role,
        SyncRolePermissions $syncRolePermissions,
    ): RedirectResponse {
        $actor = $request->user();
        abort_unless($actor instanceof User, 403);
        $codes = array_values(array_filter(
            $request->array('permissions'),
            static fn (mixed $code): bool => is_string($code),
        ));
        $permissionIds = array_values(Permission::query()
            ->whereIn('code', $codes)
            ->get(['id'])
            ->map(static fn (Permission $permission): int => (int) $permission->getKey())
            ->all());
        $syncRolePermissions->handle(
            $actor,
            $role,
            $permissionIds,
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return back()->with('status', 'Role permissions updated.');
    }
}
