@extends('layouts.app')

@section('title', 'Reauthenticate')

@section('content')
    <h1 class="h3 mb-3">Confirm it is you</h1>

    @if (session('status'))
        <div class="alert alert-info" role="status">{{ session('status') }}</div>
    @endif

    @if ($stage === 'start')
        <p>Start a fresh email and authenticator verification before continuing.</p>
        <form method="POST" action="{{ route('identity.reauthentication.begin') }}">
            @csrf
            <input type="hidden" name="return_route" value="{{ session('identity.reauthentication_return_route', 'identity.security.index') }}">
            <button class="btn btn-primary" type="submit">Send verification code</button>
        </form>
    @else
        <p>{{ $stage === 'otp' ? 'Enter the code sent to your verified email address.' : 'Enter an authenticator code or one recovery code.' }}</p>
        <form method="POST" action="{{ $stage === 'otp' ? route('identity.reauthentication.verify') : route('identity.reauthentication.mfa.complete') }}">
            @csrf
            <label class="form-label" for="code">Verification code</label>
            <input class="form-control" id="code" name="code" autocomplete="one-time-code" required>
            @error('code')<div class="text-danger" role="alert">{{ $message }}</div>@enderror
            <button class="btn btn-primary mt-3" type="submit">Verify</button>
        </form>
    @endif
@endsection
