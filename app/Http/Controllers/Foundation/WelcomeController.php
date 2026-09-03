<?php

declare(strict_types=1);

namespace App\Http\Controllers\Foundation;

use Illuminate\Contracts\View\View;

final class WelcomeController
{
    public function __invoke(): View
    {
        return view('welcome');
    }
}
