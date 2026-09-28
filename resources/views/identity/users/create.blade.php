@extends('layouts.app')

@section('title', 'Invite user')

@section('content')
    <h1 class="h2">Invite user</h1>
    @if ($errors->any()) <div class="alert alert-danger"><ul class="mb-0">@foreach ($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul></div> @endif
    <form method="POST" action="{{ route('admin.users.store') }}" class="vstack gap-3">
        @csrf
        <label class="form-label">Employee number <input class="form-control" name="employee_number" value="{{ old('employee_number') }}"></label>
        <label class="form-label">Name <input class="form-control" name="name" required value="{{ old('name') }}"></label>
        <label class="form-label">Email <input class="form-control" type="email" name="email" required value="{{ old('email') }}"></label>
        <label class="form-label">Timezone <input class="form-control" name="timezone" required value="{{ old('timezone', 'UTC') }}"></label>
        @if ($canAssignRoles)
            <fieldset class="border rounded p-3">
                <legend class="h5">Optional initial assignment</legend>
                <label class="form-label">Role
                    <select class="form-select" name="assignments[0][role]">
                        <option value="">No initial role</option>
                        @foreach ($roles as $role)<option value="{{ $role->public_id }}">{{ $role->name }}</option>@endforeach
                    </select>
                </label>
                <label class="form-label">Scope
                    <select class="form-select" name="assignments[0][scope_type]">
                        <option value="GLOBAL">Global</option><option value="APPLICATION">Application</option>
                    </select>
                </label>
                <label class="form-label">Application
                    <select class="form-select" name="assignments[0][application]">
                        <option value="">None</option>
                        @foreach ($applications as $application)<option value="{{ $application->public_id }}">{{ $application->name }}</option>@endforeach
                    </select>
                </label>
            </fieldset>
        @endif
        <button class="btn btn-primary align-self-start" type="submit">Create and invite</button>
    </form>
@endsection
