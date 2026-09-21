@extends('layouts.app')

@section('title', 'Applications | Release Governance')

@section('content')
    <div class="d-flex align-items-center justify-content-between mb-4">
        <div>
            <h1 class="h3 mb-1">Applications</h1>
            <p class="text-body-secondary mb-0">Manage the application identities used for scoped access.</p>
        </div>
        <a class="btn btn-primary" href="{{ route('admin.applications.create') }}">Create application</a>
    </div>

    @if (session('status'))
        <div class="alert alert-success" role="status">{{ session('status') }}</div>
    @endif

    <div class="card border-0 shadow-sm">
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead>
                    <tr>
                        <th scope="col">Name</th>
                        <th scope="col">Code</th>
                        <th scope="col">State</th>
                        <th scope="col" class="text-end">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    @forelse ($applications as $application)
                        <tr>
                            <td>{{ $application->name }}</td>
                            <td><code>{{ $application->code }}</code></td>
                            <td>
                                <span class="badge {{ $application->is_active ? 'text-bg-success' : 'text-bg-secondary' }}">
                                    {{ $application->is_active ? 'Active' : 'Inactive' }}
                                </span>
                            </td>
                            <td class="text-end">
                                <a class="btn btn-sm btn-outline-primary" href="{{ route('admin.applications.edit', $application) }}">
                                    Edit
                                </a>
                                <form class="d-inline" method="POST" action="{{ route('admin.applications.state.update', $application) }}">
                                    @csrf
                                    @method('PATCH')
                                    <input type="hidden" name="is_active" value="{{ $application->is_active ? '0' : '1' }}">
                                    <button class="btn btn-sm {{ $application->is_active ? 'btn-outline-danger' : 'btn-outline-success' }}" type="submit">
                                        {{ $application->is_active ? 'Deactivate' : 'Activate' }}
                                    </button>
                                </form>
                            </td>
                        </tr>
                    @empty
                        <tr>
                            <td colspan="4" class="text-center text-body-secondary py-4">No applications have been created.</td>
                        </tr>
                    @endforelse
                </tbody>
            </table>
        </div>
    </div>

    <div class="mt-3">{{ $applications->links() }}</div>
@endsection
