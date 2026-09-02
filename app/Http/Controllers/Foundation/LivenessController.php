<?php

declare(strict_types=1);

namespace App\Http\Controllers\Foundation;

use Illuminate\Http\JsonResponse;

final class LivenessController
{
    public function __invoke(): JsonResponse
    {
        return response()->json(['status' => 'ok']);
    }
}
