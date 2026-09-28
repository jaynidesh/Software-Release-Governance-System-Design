@extends('layouts.app')

@section('title', 'Roles')

@section('content')
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h2 mb-0">Roles</h1>
        <a class="btn btn-primary" href="{{ route('admin.roles.create') }}">Create role</a>
    </div>
    @if (session('status')) <div class="alert alert-success">{{ session('status') }}</div> @endif
    <div class="table-responsive">
        <table class="table align-middle">
            <thead><tr><th>Name</th><th>Code</th><th>State</th><th>Permissions</th><th>Assignments</th><th></th></tr></thead>
            <tbody>
            @foreach ($roles as $role)
                <tr>
                    <td>{{ $role->name }} @if ($role->is_system)<span class="badge text-bg-secondary">System</span>@endif</td>
                    <td><code>{{ $role->code }}</code></td>
                    <td>{{ $role->is_active ? 'Active' : 'Inactive' }}</td>
                    <td>{{ $role->permissions_count }}</td>
                    <td>{{ $role->assignments_count }}</td>
                    <td><a href="{{ route('admin.roles.show', $role) }}">Manage</a></td>
                </tr>
            @endforeach
            </tbody>
        </table>
    </div>
    {{ $roles->links() }}
@endsection
