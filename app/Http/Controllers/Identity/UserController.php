<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Users\CreateInvitedUser;
use App\Application\Identity\Users\UpdateUser;
use App\Domain\Identity\Enums\PermissionScope;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Users\StoreUserRequest;
use App\Http\Requests\Identity\Users\UpdateUserRequest;
use App\Models\Application;
use App\Models\Role;
use App\Models\User;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class UserController extends Controller
{
    public function index(): View
    {
        Gate::authorize('admin.users');
        $users = User::query()
            ->withCount(['roleAssignments', 'authSessions'])
            ->orderBy('name')
            ->orderBy('id')
            ->paginate((int) config('identity.administration.per_page', 15));

        return view('identity.users.index', ['users' => $users]);
    }

    public function create(): View
    {
        Gate::authorize('admin.users');

        return view('identity.users.create', [
            'roles' => Role::query()->where('is_active', true)->orderBy('name')->orderBy('id')->get(),
            'applications' => Application::query()->where('is_active', true)->orderBy('name')->orderBy('id')->get(),
            'canAssignRoles' => Gate::allows('admin.roles'),
        ]);
    }

    public function store(StoreUserRequest $request, CreateInvitedUser $createUser): RedirectResponse
    {
        $actor = $this->actor($request->user());
        $data = $request->validated();
        $assignments = $this->initialAssignments($request);
        $user = $createUser->handle(
            $actor,
            [
                'employee_number' => $data['employee_number'] ?? null,
                'name' => $data['name'],
                'email' => $data['email'],
                'timezone' => $data['timezone'],
            ],
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
            $assignments,
        );

        return redirect()->route('admin.users.show', $user)->with('status', 'User invited.');
    }

    public function show(User $user): View
    {
        Gate::authorize('admin.users');
        $user->load([
            'roleAssignments' => static fn ($query) => $query
                ->with(['role:id,public_id,name,code', 'application:id,public_id,name,code'])
                ->orderByDesc('starts_at')
                ->orderByDesc('id'),
            'mfaMethods' => static fn ($query) => $query
                ->select(['id', 'user_id', 'type', 'confirmed_at', 'disabled_at']),
        ])->loadCount('authSessions');

        return view('identity.users.show', [
            'managedUser' => $user,
            'roles' => Role::query()->where('is_active', true)->orderBy('name')->orderBy('id')->get(),
            'applications' => Application::query()->where('is_active', true)->orderBy('name')->orderBy('id')->get(),
            'canManageRoles' => Gate::allows('admin.roles'),
        ]);
    }

    public function edit(User $user): View
    {
        Gate::authorize('admin.users');

        return view('identity.users.edit', ['managedUser' => $user]);
    }

    public function update(UpdateUserRequest $request, User $user, UpdateUser $updateUser): RedirectResponse
    {
        $data = $request->validated();
        $updateUser->handle(
            $this->actor($request->user()),
            $user,
            [
                'employee_number' => $data['employee_number'] ?? null,
                'name' => $data['name'],
                'email' => $data['email'],
                'timezone' => $data['timezone'],
            ],
            $request->ip(),
            $request->userAgent(),
            $request->attributes->getString('correlation_id') ?: null,
        );

        return redirect()->route('admin.users.show', $user)->with('status', 'User updated.');
    }

    private function actor(mixed $user): User
    {
        abort_unless($user instanceof User, 403);

        return $user;
    }

    /**
     * @return list<array{role: Role, application: Application|null, starts_at: CarbonInterface, ends_at: CarbonInterface|null}>
     */
    private function initialAssignments(StoreUserRequest $request): array
    {
        $result = [];

        foreach ($request->array('assignments') as $assignment) {
            if (! is_array($assignment)) {
                continue;
            }

            $roleReference = $assignment['role'] ?? null;
            $scopeType = $assignment['scope_type'] ?? null;
            $applicationReference = $assignment['application'] ?? null;
            $startsAt = $assignment['starts_at'] ?? null;
            $endsAt = $assignment['ends_at'] ?? null;

            if (! is_string($roleReference) || ! is_string($scopeType)) {
                continue;
            }

            $application = $scopeType === PermissionScope::Application->value && is_string($applicationReference)
                ? Application::query()->where('public_id', $applicationReference)->firstOrFail()
                : null;
            $result[] = [
                'role' => Role::query()->where('public_id', $roleReference)->firstOrFail(),
                'application' => $application,
                'starts_at' => is_string($startsAt) ? CarbonImmutable::parse($startsAt) : now(),
                'ends_at' => is_string($endsAt) ? CarbonImmutable::parse($endsAt) : null,
            ];
        }

        return $result;
    }
}
