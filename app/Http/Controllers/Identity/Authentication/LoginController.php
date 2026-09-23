<?php

declare(strict_types=1);

namespace App\Http\Controllers\Identity\Authentication;

use App\Http\Controllers\Controller;
use Illuminate\Http\Response;

final class LoginController extends Controller
{
    public function __invoke(): Response
    {
        return response()->view('identity.auth.login')
            ->header('Cache-Control', 'no-store, private');
    }
}
