@extends('layouts.guest')

@section('title', 'Sign in | Release Governance')

@section('content')
    <section class="card border-0 shadow-sm">
        <div class="card-body p-4">
            <h1 class="h3 mb-3">Sign in</h1>
            <p class="text-body-secondary">We will send a one-time code to your registered email address.</p>
            <form method="POST" action="{{ route('identity.auth.otp.store') }}">
                @csrf
                <div class="mb-3">
                    <label for="email" class="form-label">Email address</label>
                    <input id="email" name="email" type="email" class="form-control" autocomplete="email" required autofocus>
                    @error('email')<div class="invalid-feedback d-block">{{ $message }}</div>@enderror
                </div>
                <button type="submit" class="btn btn-primary w-100">Send code</button>
            </form>
        </div>
    </section>
@endsection
