@extends('layouts.app')

@section('title', 'Create role')

@section('content')
    <h1 class="h2">Create role</h1>
    @if ($errors->any()) <div class="alert alert-danger"><ul class="mb-0">@foreach ($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul></div> @endif
    <form method="POST" action="{{ route('admin.roles.store') }}" class="vstack gap-3">
        @csrf
        <label class="form-label">Code <input class="form-control" name="code" required value="{{ old('code') }}"></label>
        <label class="form-label">Name <input class="form-control" name="name" required value="{{ old('name') }}"></label>
        <label class="form-label">Description <textarea class="form-control" name="description">{{ old('description') }}</textarea></label>
        <button class="btn btn-primary align-self-start" type="submit">Create role</button>
    </form>
@endsection
