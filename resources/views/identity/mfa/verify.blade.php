@extends('layouts.guest')

@section('title', 'Verify authenticator')

@section('content')
    <h1 class="h3 mb-3">Verify your authenticator</h1>
    <form method="POST" action="{{ route('identity.mfa.verify.store') }}">
        @csrf
        <label for="code">Authenticator or recovery code</label>
        <input id="code" name="code" autocomplete="one-time-code" required>
        @error('code')<div role="alert">{{ $message }}</div>@enderror
        <button type="submit">Finish sign in</button>
    </form>
    <form method="POST" action="{{ route('identity.auth.pending.cancel') }}">
        @csrf
        <button type="submit">Cancel sign in</button>
    </form>
@endsection
