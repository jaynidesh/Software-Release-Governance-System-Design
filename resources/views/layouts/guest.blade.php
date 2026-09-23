<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'Sign in | Release Governance')</title>
    @vite(['resources/sass/app.scss', 'resources/js/app.js'])
</head>
<body class="bg-body-tertiary">
    <a class="skip-link btn btn-light" href="#main-content">Skip to main content</a>
    <main id="main-content" class="container py-5" tabindex="-1">
        <div class="row justify-content-center">
            <div class="col-12 col-md-7 col-lg-5">
                @yield('content')
            </div>
        </div>
    </main>
</body>
</html>
