@extends('layouts.guest')

@section('title', 'Recovery codes')

@section('content')
    <h1 class="h3 mb-3">Store these recovery codes</h1>
    @if ($initial)
        <p>Each code can be used only once. They will not be displayed again.</p>
        <ul>
            @foreach ($codes as $code)
                <li><code data-recovery-code="{{ $code }}">{{ $code }}</code></li>
            @endforeach
        </ul>
    @else
        <p>Your recovery codes were already displayed and cannot be shown again.</p>
    @endif
    <form method="POST" action="{{ route('identity.mfa.recovery.store') }}">
        @csrf
        <label><input type="checkbox" name="acknowledged" value="1" required> I stored my recovery codes securely.</label>
        <button type="submit">Finish sign in</button>
    </form>
@endsection
