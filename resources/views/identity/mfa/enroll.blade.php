@extends('layouts.guest')

@section('title', 'Set up authenticator')

@section('content')
    <h1 class="h3 mb-3">Set up your authenticator</h1>
    @if ($secret !== null && $svg !== null)
        <p>Scan this locally generated QR code or enter the manual setup key.</p>
        <div aria-label="Authenticator QR code">{!! $svg !!}</div>
        <p><strong>Manual setup key:</strong> <code>{{ $secret }}</code></p>
    @else
        <p>The setup key was already shown. Enter the current code from the authenticator you configured.</p>
    @endif
    <form method="POST" action="{{ route('identity.mfa.enroll.store') }}">
        @csrf
        <label for="code">Authenticator code</label>
        <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>
        @error('code')<div role="alert">{{ $message }}</div>@enderror
        <button type="submit">Confirm authenticator</button>
    </form>
    <form method="POST" action="{{ route('identity.auth.pending.cancel') }}">
        @csrf
        <button type="submit">Cancel sign in</button>
    </form>
@endsection
