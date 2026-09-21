<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity;

use App\Application\Identity\Applications\ChangeApplicationState;
use App\Http\Controllers\Controller;
use App\Http\Requests\Identity\Applications\ChangeApplicationStateRequest;
use App\Models\Application;
use App\Models\User;
use Illuminate\Http\RedirectResponse;

final class ApplicationStateController extends Controller
{
    public function __invoke(
        ChangeApplicationStateRequest $request,
        Application $application,
        ChangeApplicationState $changeApplicationState,
    ): RedirectResponse {
        $actor = $request->user();

        if (! $actor instanceof User) {
            abort(403);
        }

        $changeApplicationState->handle($actor, $application, $request->boolean('is_active'));

        return redirect()->route('admin.applications.index')
            ->with('status', 'Application state updated.');
    }
}
