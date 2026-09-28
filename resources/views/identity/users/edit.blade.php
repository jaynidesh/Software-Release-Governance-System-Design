@extends('layouts.app')

@section('title', 'Edit user')

@section('content')
    <h1 class="h2">Edit {{ $managedUser->name }}</h1>
    @if ($errors->any()) <div class="alert alert-danger"><ul class="mb-0">@foreach ($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul></div> @endif
    <form method="POST" action="{{ route('admin.users.update', $managedUser) }}" class="vstack gap-3">
        @csrf @method('PATCH')
        <label class="form-label">Employee number <input class="form-control" name="employee_number" value="{{ old('employee_number', $managedUser->employee_number) }}"></label>
        <label class="form-label">Name <input class="form-control" name="name" required value="{{ old('name', $managedUser->name) }}"></label>
        <label class="form-label">Email <input class="form-control" type="email" name="email" required value="{{ old('email', $managedUser->email) }}"></label>
        <label class="form-label">Timezone <input class="form-control" name="timezone" required value="{{ old('timezone', $managedUser->timezone) }}"></label>
        <p class="text-muted">Changing email revokes sessions and sends a new activation invitation.</p>
        <button class="btn btn-primary align-self-start" type="submit">Save</button>
    </form>
@endsection
