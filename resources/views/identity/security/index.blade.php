@extends('layouts.app')

@section('title', 'Security')

@section('content')
    <h1 class="h3 mb-3">Security</h1>
    <p>Review and revoke browsers that are signed in to your account.</p>

    @isset($recoveryCodes)
        <div class="alert alert-warning">
            <h2 class="h5">Store these recovery codes</h2>
            <p>They will not be shown again.</p>
            <ul>
                @foreach ($recoveryCodes as $code)
                    <li><code>{{ $code }}</code></li>
                @endforeach
            </ul>
        </div>
    @endisset

    @isset($totpRotation)
        <div class="alert alert-warning">
            <h2 class="h5">Set up the replacement authenticator</h2>
            <div aria-label="Authenticator QR code">{!! $totpRotation['svg'] !!}</div>
            <p><strong>Manual setup key:</strong> <code>{{ $totpRotation['secret'] }}</code></p>
        </div>
    @endisset

    <div class="table-responsive">
        <table class="table align-middle">
            <thead>
                <tr>
                    <th>Started</th>
                    <th>Last activity</th>
                    <th>IP address</th>
                    <th>Device</th>
                    <th><span class="visually-hidden">Actions</span></th>
                </tr>
            </thead>
            <tbody>
                @foreach ($sessions as $authSession)
                    <tr>
                        <td>{{ $authSession->started_at }}</td>
                        <td>{{ $authSession->last_seen_at }}</td>
                        <td>{{ $authSession->ip_address ?? 'Unknown' }}</td>
                        <td>{{ str_contains(mb_strtolower((string) $authSession->user_agent), 'mobile') ? 'Mobile browser' : 'Browser' }}</td>
                        <td>
                            <form method="POST" action="{{ route('identity.sessions.destroy', $authSession) }}">
                                @csrf
                                @method('DELETE')
                                <button class="btn btn-sm btn-outline-danger" type="submit">
                                    {{ hash_equals($currentSessionId, $authSession->session_id) ? 'Sign out this browser' : 'Revoke' }}
                                </button>
                            </form>
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>

    <form method="POST" action="{{ route('identity.sessions.destroy-all') }}">
        @csrf
        @method('DELETE')
        <button class="btn btn-danger" type="submit">Sign out all sessions</button>
    </form>

    <hr>
    <h2 class="h4">Credentials</h2>
    <form class="d-inline" method="POST" action="{{ route('identity.security.recovery-codes.store') }}">
        @csrf
        <button class="btn btn-outline-primary" type="submit">Generate new recovery codes</button>
    </form>
    <form class="d-inline" method="POST" action="{{ route('identity.security.totp.store') }}">
        @csrf
        <button class="btn btn-outline-primary" type="submit">Rotate authenticator</button>
    </form>
@endsection
