@extends('layouts.app')

@section('title', 'Create application | Release Governance')

@section('content')
    <div class="row justify-content-center">
        <div class="col-xl-7">
            <div class="card border-0 shadow-sm">
                <div class="card-body p-4">
                    <h1 class="h3">Create application</h1>
                    <p class="text-body-secondary">Create the stable identity used by scoped roles and future release configuration.</p>

                    <form method="POST" action="{{ route('admin.applications.store') }}">
                        @csrf
                        <div class="mb-3">
                            <label class="form-label" for="code">Code</label>
                            <input class="form-control @error('code') is-invalid @enderror" id="code" name="code" value="{{ old('code') }}" maxlength="100" required>
                            @error('code')<div class="invalid-feedback">{{ $message }}</div>@enderror
                        </div>
                        <div class="mb-4">
                            <label class="form-label" for="name">Name</label>
                            <input class="form-control @error('name') is-invalid @enderror" id="name" name="name" value="{{ old('name') }}" maxlength="255" required>
                            @error('name')<div class="invalid-feedback">{{ $message }}</div>@enderror
                        </div>
                        <div class="d-flex gap-2">
                            <button class="btn btn-primary" type="submit">Create application</button>
                            <a class="btn btn-outline-secondary" href="{{ route('admin.applications.index') }}">Cancel</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
@endsection
