<?php

declare(strict_types=1);

namespace App\Http\Controllers\Foundation;

use App\Contracts\Foundation\ReadinessCheck;
use Illuminate\Http\JsonResponse;

final readonly class ReadinessController
{
    public function __construct(private ReadinessCheck $readiness) {}

    public function __invoke(): JsonResponse
    {
        $ready = $this->readiness->check();

        return response()->json(
            ['status' => $ready ? 'ready' : 'unavailable'],
            $ready ? 200 : 503,
        );
    }
}
