@extends('layouts.app')

@section('title', 'Users')

@section('content')
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h2 mb-0">Users</h1>
        <a class="btn btn-primary" href="{{ route('admin.users.create') }}">Invite user</a>
    </div>
    @if (session('status')) <div class="alert alert-success">{{ session('status') }}</div> @endif
    <div class="table-responsive">
        <table class="table align-middle">
            <thead><tr><th>Name</th><th>Email</th><th>State</th><th>Roles</th><th>Sessions</th><th></th></tr></thead>
            <tbody>
            @foreach ($users as $managedUser)
                <tr>
                    <td>{{ $managedUser->name }}</td>
                    <td>{{ $managedUser->email }}</td>
                    <td>{{ $managedUser->state->value }}</td>
                    <td>{{ $managedUser->role_assignments_count }}</td>
                    <td>{{ $managedUser->auth_sessions_count }}</td>
                    <td><a href="{{ route('admin.users.show', $managedUser) }}">Manage</a></td>
                </tr>
            @endforeach
            </tbody>
        </table>
    </div>
    {{ $users->links() }}
@endsection
