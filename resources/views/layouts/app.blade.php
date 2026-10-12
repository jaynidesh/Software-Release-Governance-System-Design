<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'Release Governance')</title>
    @vite(['resources/sass/app.scss', 'resources/js/app.js'])
</head>
<body>
    <a class="skip-link btn btn-light" href="#main-content">Skip to main content</a>
    <x-app-navbar />
    <div class="d-flex min-vh-100">
        <x-app-sidebar />
        <main id="main-content" class="container-fluid p-4" tabindex="-1">
            @if (session('warning'))
                <div class="alert alert-warning" role="alert">
                    {{ session('warning') }}
                    <a href="{{ route('identity.security.index') }}">Manage recovery codes</a>
                </div>
            @endif
            @yield('content')
        </main>
    </div>
</body>
</html>
