@extends('layouts.app')

@section('title', 'Role assignments')

@section('content')
    <h1 class="h2">Role assignments</h1>
    @if (session('status')) <div class="alert alert-success">{{ session('status') }}</div> @endif
    @if ($errors->any()) <div class="alert alert-danger"><ul class="mb-0">@foreach ($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul></div> @endif
    @foreach ($users as $managedUser)
        <section class="card mb-3">
            <div class="card-body">
                <h2 class="h5">{{ $managedUser->name }}</h2>
                <ul>
                    @forelse ($managedUser->roleAssignments as $assignment)
                        <li>
                            {{ $assignment->role->name }} — {{ $assignment->application?->name ?? 'Global' }}
                            @if ($assignment->revoked_at === null)
                                <form method="POST" action="{{ route('admin.users.role-assignments.destroy', [$managedUser, $assignment]) }}" class="d-inline">
                                    @csrf @method('DELETE')
                                    <button class="btn btn-sm btn-outline-danger">Revoke</button>
                                </form>
                            @endif
                        </li>
                    @empty
                        <li>No role assignments.</li>
                    @endforelse
                </ul>
                <form method="POST" action="{{ route('admin.users.role-assignments.store', $managedUser) }}" class="row g-2">
                    @csrf
                    <div class="col-md-3"><label class="form-label">Role<select class="form-select" name="role">@foreach ($roles as $role)<option value="{{ $role->public_id }}">{{ $role->name }}</option>@endforeach</select></label></div>
                    <div class="col-md-2"><label class="form-label">Scope<select class="form-select" name="scope_type"><option value="GLOBAL">Global</option><option value="APPLICATION">Application</option></select></label></div>
                    <div class="col-md-3"><label class="form-label">Application<select class="form-select" name="application"><option value="">None</option>@foreach ($applications as $application)<option value="{{ $application->public_id }}">{{ $application->name }}</option>@endforeach</select></label></div>
                    <div class="col-md-2"><label class="form-label">Starts<input class="form-control" type="datetime-local" name="starts_at"></label></div>
                    <div class="col-md-2"><label class="form-label">Ends<input class="form-control" type="datetime-local" name="ends_at"></label></div>
                    <div><button class="btn btn-primary">Assign role</button></div>
                </form>
            </div>
        </section>
    @endforeach
    {{ $users->links() }}
@endsection
