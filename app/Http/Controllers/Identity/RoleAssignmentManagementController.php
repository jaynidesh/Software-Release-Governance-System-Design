<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Http\Controllers\Controller;
use App\Models\Application;
use App\Models\Role;
use App\Models\User;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class RoleAssignmentManagementController extends Controller
{
    public function __invoke(): View
    {
        Gate::authorize('admin.roles');
        $users = User::query()
            ->select(['id', 'public_id', 'name'])
            ->with([
                'roleAssignments' => static fn ($query) => $query
                    ->with(['role:id,public_id,name,code', 'application:id,public_id,name,code'])
                    ->orderByDesc('starts_at')
                    ->orderByDesc('id'),
            ])
            ->orderBy('name')
            ->orderBy('id')
            ->paginate((int) config('identity.administration.per_page', 15));

        return view('identity.assignments.index', [
            'users' => $users,
            'roles' => Role::query()->where('is_active', true)->orderBy('name')->orderBy('id')->get(),
            'applications' => Application::query()
                ->where('is_active', true)
                ->orderBy('name')
                ->orderBy('id')
                ->get(),
        ]);
    }
}
