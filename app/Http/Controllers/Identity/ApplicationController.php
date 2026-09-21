<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Applications\CreateApplication;
use App\Application\Identity\Applications\UpdateApplication;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Applications\StoreApplicationRequest;
use App\Http\Requests\Identity\Applications\UpdateApplicationRequest;
use App\Models\Application;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Illuminate\View\View;

final class ApplicationController extends Controller
{
    public function index(): View
    {
        Gate::authorize('viewAny', Application::class);

        $applications = Application::query()
            ->orderBy('name')
            ->orderBy('id')
            ->paginate(15);

        return view('identity.applications.index', ['applications' => $applications]);
    }

    public function create(): View
    {
        Gate::authorize('viewAny', Application::class);

        return view('identity.applications.create');
    }

    public function store(StoreApplicationRequest $request, CreateApplication $createApplication): RedirectResponse
    {
        $actor = $request->user();

        if (! $actor instanceof User) {
            abort(403);
        }

        $createApplication->handle($actor, [
            'code' => $request->string('code')->toString(),
            'name' => $request->string('name')->toString(),
        ]);

        return redirect()->route('admin.applications.index')
            ->with('status', 'Application created.');
    }

    public function edit(Application $application): View
    {
        Gate::authorize('view', $application);

        return view('identity.applications.edit', ['application' => $application]);
    }

    public function update(
        UpdateApplicationRequest $request,
        Application $application,
        UpdateApplication $updateApplication,
    ): RedirectResponse {
        $actor = $request->user();

        if (! $actor instanceof User) {
            abort(403);
        }

        $updateApplication->handle($actor, $application, [
            'name' => $request->string('name')->toString(),
        ]);

        return redirect()->route('admin.applications.index')
            ->with('status', 'Application updated.');
    }
}
