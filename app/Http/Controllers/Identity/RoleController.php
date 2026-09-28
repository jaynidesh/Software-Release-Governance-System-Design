<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Roles\ChangeRoleState;
use App\Application\Identity\Roles\CreateRole;
use App\Application\Identity\Roles\UpdateRole;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Roles\ChangeRoleStateRequest;
use App\Http\Requests\Identity\Roles\StoreRoleRequest;
use App\Http\Requests\Identity\Roles\UpdateRoleRequest;
use App\Models\Permission;
use App\Models\Role;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class RoleController extends Controller
{
    public function index(): View
    {
        Gate::authorize('admin.roles');
        $roles = Role::query()
            ->withCount(['permissions', 'assignments'])
            ->orderBy('name')
            ->orderBy('id')
            ->paginate((int) config('identity.administration.per_page', 15));

        return view('identity.roles.index', ['roles' => $roles]);
    }

    public function create(): View
    {
        Gate::authorize('admin.roles');

        return view('identity.roles.create');
    }

    public function store(StoreRoleRequest $request, CreateRole $createRole): RedirectResponse
    {
        $data = $request->validated();
        $role = $createRole->handle(
            $this->actor($request->user()),
            [
                'code' => $data['code'],
                'name' => $data['name'],
                'description' => $data['description'] ?? null,
            ],
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return redirect()->route('admin.roles.show', $role)->with('status', 'Role created.');
    }

    public function show(Role $role): View
    {
        Gate::authorize('admin.roles');
        $role->load(['permissions' => static fn ($query) => $query->orderBy('code')])
            ->loadCount('assignments');

        return view('identity.roles.show', [
            'role' => $role,
            'permissions' => Permission::query()->orderBy('scope_type')->orderBy('code')->get(),
        ]);
    }

    public function edit(Role $role): View
    {
        Gate::authorize('admin.roles');

        return view('identity.roles.edit', ['role' => $role]);
    }

    public function update(UpdateRoleRequest $request, Role $role, UpdateRole $updateRole): RedirectResponse
    {
        $data = $request->validated();
        $updateRole->handle(
            $this->actor($request->user()),
            $role,
            [
                'code' => $data['code'],
                'name' => $data['name'],
                'description' => $data['description'] ?? null,
            ],
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return redirect()->route('admin.roles.show', $role)->with('status', 'Role updated.');
    }

    public function changeState(
        ChangeRoleStateRequest $request,
        Role $role,
        ChangeRoleState $changeRoleState,
    ): RedirectResponse {
        $changeRoleState->handle(
            $this->actor($request->user()),
            $role,
            $request->boolean('is_active'),
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return back()->with('status', 'Role state updated.');
    }

    private function actor(mixed $user): User
    {
        abort_unless($user instanceof User, 403);

        return $user;
    }
}
