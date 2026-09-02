<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

final class AssignCorrelationId
{
    public function handle(Request $request, Closure $next): Response
    {
        $id = Str::uuid()->toString();
        $request->attributes->set('correlation_id', $id);
        Log::shareContext(['correlation_id' => $id]);

        $response = $next($request);
        $response->headers->set('X-Correlation-ID', $id);

        return $response;
    }
}
