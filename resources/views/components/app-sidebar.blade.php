<aside class="app-sidebar bg-white border-end p-3">
    <nav aria-label="Primary navigation">
        <ul class="nav nav-pills flex-column gap-1">
            <li class="nav-item">
                <a class="nav-link active" aria-current="page" href="{{ route('home') }}">
                    <i class="bi bi-house-door me-2" aria-hidden="true"></i>Home
                </a>
            </li>
            @can('admin.applications')
                <li class="nav-item">
                    <a class="nav-link" href="{{ route('admin.applications.index') }}">
                        <i class="bi bi-grid me-2" aria-hidden="true"></i>Applications
                    </a>
                </li>
            @endcan
        </ul>
    </nav>
</aside>
