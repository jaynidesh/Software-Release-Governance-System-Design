@extends('layouts.app')

@section('title', 'Manage role')

@section('content')
    <div class="d-flex justify-content-between"><h1 class="h2">{{ $role->name }}</h1><a href="{{ route('admin.roles.edit', $role) }}">Edit</a></div>
    @if (session('status')) <div class="alert alert-success">{{ session('status') }}</div> @endif
    @if ($errors->any()) <div class="alert alert-danger"><ul class="mb-0">@foreach ($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul></div> @endif
    <dl class="row">
        <dt class="col-sm-3">Code</dt><dd class="col-sm-9"><code>{{ $role->code }}</code></dd>
        <dt class="col-sm-3">System role</dt><dd class="col-sm-9">{{ $role->is_system ? 'Yes' : 'No' }}</dd>
        <dt class="col-sm-3">State</dt><dd class="col-sm-9">{{ $role->is_active ? 'Active' : 'Inactive' }}</dd>
        <dt class="col-sm-3">Assignments</dt><dd class="col-sm-9">{{ $role->assignments_count }}</dd>
    </dl>
    <form method="POST" action="{{ route('admin.roles.state.update', $role) }}" class="mb-4">
        @csrf @method('PATCH')
        <input type="hidden" name="is_active" value="{{ $role->is_active ? '0' : '1' }}">
        <button class="btn btn-outline-{{ $role->is_active ? 'danger' : 'success' }}">{{ $role->is_active ? 'Deactivate' : 'Activate' }}</button>
    </form>
    <h2 class="h4">Permission composition</h2>
    <form method="POST" action="{{ route('admin.roles.permissions.update', $role) }}">
        @csrf @method('PUT')
        <div class="row">
            @foreach ($permissions as $permission)
                @php($mandatoryAdministratorPermission = $role->code === 'administrator' && str_starts_with($permission->code, 'admin.'))
                <div class="col-md-6 col-xl-4 mb-2">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="permissions[]" value="{{ $permission->code }}" id="permission-{{ $permission->id }}"
                            @checked($role->permissions->contains('id', $permission->id)) @disabled($mandatoryAdministratorPermission)>
                        @if ($mandatoryAdministratorPermission)<input type="hidden" name="permissions[]" value="{{ $permission->code }}">@endif
                        <label class="form-check-label" for="permission-{{ $permission->id }}"><code>{{ $permission->code }}</code> <span class="text-muted">({{ $permission->scope_type->value }})</span></label>
                    </div>
                </div>
            @endforeach
        </div>
        <button class="btn btn-primary mt-2">Save permissions</button>
    </form>
@endsection
