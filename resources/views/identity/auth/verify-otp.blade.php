@extends('layouts.guest')

@section('title', 'Verify code | Release Governance')

@section('content')
    <section class="card border-0 shadow-sm">
        <div class="card-body p-4">
            <h1 class="h3 mb-3">Enter your code</h1>
            @if (session('status'))
                <div class="alert alert-info" role="status">{{ session('status') }}</div>
            @endif
            <form method="POST" action="{{ route('identity.auth.otp.verify') }}">
                @csrf
                <div class="mb-3">
                    <label for="code" class="form-label">One-time code</label>
                    <input id="code" name="code" type="text" class="form-control" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" required autofocus>
                    @error('code')<div class="invalid-feedback d-block">{{ $message }}</div>@enderror
                </div>
                <button type="submit" class="btn btn-primary w-100">Verify</button>
            </form>
        </div>
    </section>
@endsection
