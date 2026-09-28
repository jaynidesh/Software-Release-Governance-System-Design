@extends('layouts.app')

@section('title', 'Edit role')

@section('content')
    <h1 class="h2">Edit {{ $role->name }}</h1>
    @if ($errors->any()) <div class="alert alert-danger"><ul class="mb-0">@foreach ($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul></div> @endif
    <form method="POST" action="{{ route('admin.roles.update', $role) }}" class="vstack gap-3">
        @csrf @method('PATCH')
        <label class="form-label">Code <input class="form-control" name="code" required value="{{ old('code', $role->code) }}" @disabled($role->is_system)></label>
        @if ($role->is_system)<input type="hidden" name="code" value="{{ $role->code }}">@endif
        <label class="form-label">Name <input class="form-control" name="name" required value="{{ old('name', $role->name) }}"></label>
        <label class="form-label">Description <textarea class="form-control" name="description">{{ old('description', $role->description) }}</textarea></label>
        <button class="btn btn-primary align-self-start" type="submit">Save role</button>
    </form>
@endsection
