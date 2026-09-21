@extends('layouts.app')

@section('title', 'Edit application | Release Governance')

@section('content')
    <div class="row justify-content-center">
        <div class="col-xl-7">
            <div class="card border-0 shadow-sm">
                <div class="card-body p-4">
                    <h1 class="h3">Edit application</h1>
                    <p class="text-body-secondary">The application code is a stable authorization identity and cannot be changed.</p>

                    <form method="POST" action="{{ route('admin.applications.update', $application) }}">
                        @csrf
                        @method('PATCH')
                        <div class="mb-3">
                            <label class="form-label" for="code">Code</label>
                            <input class="form-control" id="code" value="{{ $application->code }}" disabled>
                        </div>
                        <div class="mb-4">
                            <label class="form-label" for="name">Name</label>
                            <input class="form-control @error('name') is-invalid @enderror" id="name" name="name" value="{{ old('name', $application->name) }}" maxlength="255" required>
                            @error('name')<div class="invalid-feedback">{{ $message }}</div>@enderror
                        </div>
                        <div class="d-flex gap-2">
                            <button class="btn btn-primary" type="submit">Save changes</button>
                            <a class="btn btn-outline-secondary" href="{{ route('admin.applications.index') }}">Cancel</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
@endsection
