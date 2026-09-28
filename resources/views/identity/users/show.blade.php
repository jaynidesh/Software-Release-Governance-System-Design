@extends('layouts.app')

@section('title', 'Manage user')

@section('content')
    <div class="d-flex justify-content-between"><h1 class="h2">{{ $managedUser->name }}</h1><a href="{{ route('admin.users.edit', $managedUser) }}">Edit</a></div>
    @if (session('status')) <div class="alert alert-success">{{ session('status') }}</div> @endif
    @if ($errors->any()) <div class="alert alert-danger"><ul class="mb-0">@foreach ($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul></div> @endif
    <dl class="row">
        <dt class="col-sm-3">Email</dt><dd class="col-sm-9">{{ $managedUser->email }}</dd>
        <dt class="col-sm-3">State</dt><dd class="col-sm-9">{{ $managedUser->state->value }}</dd>
        <dt class="col-sm-3">Timezone</dt><dd class="col-sm-9">{{ $managedUser->timezone }}</dd>
        <dt class="col-sm-3">Locked until</dt><dd class="col-sm-9">{{ $managedUser->locked_until?->toIso8601String() ?? 'Not locked' }}</dd>
        <dt class="col-sm-3">Sessions</dt><dd class="col-sm-9">{{ $managedUser->auth_sessions_count }}</dd>
        <dt class="col-sm-3">MFA ready</dt><dd class="col-sm-9">{{ $managedUser->mfaMethods->contains(fn ($method) => $method->confirmed_at !== null && $method->disabled_at === null) ? 'Yes' : 'No' }}</dd>
    </dl>
    <div class="d-flex flex-wrap gap-2 mb-4">
        <form method="POST" action="{{ route('admin.users.state.update', $managedUser) }}">@csrf @method('PATCH')<input type="hidden" name="state" value="SUSPENDED"><button class="btn btn-outline-warning">Suspend</button></form>
        <form method="POST" action="{{ route('admin.users.state.update', $managedUser) }}">@csrf @method('PATCH')<input type="hidden" name="state" value="ACTIVE"><button class="btn btn-outline-success">Reactivate</button></form>
        <form method="POST" action="{{ route('admin.users.state.update', $managedUser) }}">@csrf @method('PATCH')<input type="hidden" name="state" value="DEACTIVATED"><button class="btn btn-outline-danger">Deactivate</button></form>
        <form method="POST" action="{{ route('admin.users.invitations.store', $managedUser) }}">@csrf<button class="btn btn-outline-primary">Resend invitation</button></form>
        <form method="POST" action="{{ route('admin.users.invitations.destroy', $managedUser) }}">@csrf @method('DELETE')<button class="btn btn-outline-secondary">Revoke invitation</button></form>
        <form method="POST" action="{{ route('admin.users.unlock.store', $managedUser) }}">@csrf<button class="btn btn-outline-secondary">Unlock</button></form>
        <form method="POST" action="{{ route('admin.users.sessions.destroy', $managedUser) }}">@csrf @method('DELETE')<button class="btn btn-outline-danger">Revoke sessions</button></form>
        @if (! auth()->user()->is($managedUser))
            <form method="POST" action="{{ route('admin.users.mfa.destroy', $managedUser) }}">@csrf @method('DELETE')<button class="btn btn-outline-danger">Reset MFA</button></form>
        @endif
    </div>
    <h2 class="h4">Role assignments</h2>
    <table class="table"><thead><tr><th>Role</th><th>Scope</th><th>Validity</th><th></th></tr></thead><tbody>
    @foreach ($managedUser->roleAssignments as $assignment)
        <tr><td>{{ $assignment->role->name }}</td><td>{{ $assignment->application?->name ?? 'Global' }}</td><td>{{ $assignment->starts_at->toIso8601String() }} – {{ $assignment->ends_at?->toIso8601String() ?? 'No expiry' }}</td><td>
            @if ($canManageRoles && $assignment->revoked_at === null && ! auth()->user()->is($managedUser))
                <form method="POST" action="{{ route('admin.users.role-assignments.destroy', [$managedUser, $assignment]) }}">@csrf @method('DELETE')<button class="btn btn-sm btn-outline-danger">Revoke</button></form>
            @endif
        </td></tr>
    @endforeach
    </tbody></table>
    @if ($canManageRoles && ! auth()->user()->is($managedUser))
        <form method="POST" action="{{ route('admin.users.role-assignments.store', $managedUser) }}" class="row g-2">
            @csrf
            <div class="col-md-3"><label class="form-label">Role<select class="form-select" name="role">@foreach ($roles as $role)<option value="{{ $role->public_id }}">{{ $role->name }}</option>@endforeach</select></label></div>
            <div class="col-md-2"><label class="form-label">Scope<select class="form-select" name="scope_type"><option value="GLOBAL">Global</option><option value="APPLICATION">Application</option></select></label></div>
            <div class="col-md-3"><label class="form-label">Application<select class="form-select" name="application"><option value="">None</option>@foreach ($applications as $application)<option value="{{ $application->public_id }}">{{ $application->name }}</option>@endforeach</select></label></div>
            <div class="col-md-2"><label class="form-label">Starts<input class="form-control" type="datetime-local" name="starts_at"></label></div>
            <div class="col-md-2"><label class="form-label">Ends<input class="form-control" type="datetime-local" name="ends_at"></label></div>
            <div><button class="btn btn-primary">Assign role</button></div>
        </form>
    @endif
@endsection
