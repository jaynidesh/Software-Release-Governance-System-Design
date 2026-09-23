<?php

declare(strict_types=1);

namespace App\Services\Identity;

use Illuminate\Support\Facades\RateLimiter;

final class AuthenticationThrottle
{
    public function __construct(private readonly OtpHasher $hasher) {}

    public function allowsRequest(string $normalizedIdentifier, ?string $ipAddress): bool
    {
        $identifierKey = 'identity:otp:identifier:'.$this->hasher->hashIdentifier($normalizedIdentifier);
        $ipKey = 'identity:otp:ip:'.$this->hasher->hashIdentifier($ipAddress ?? 'unknown');
        $identifierLimited = RateLimiter::tooManyAttempts(
            $identifierKey,
            (int) config('identity.otp.request_limit'),
        );
        $ipLimited = RateLimiter::tooManyAttempts(
            $ipKey,
            (int) config('identity.otp.ip_request_limit'),
        );
        $decaySeconds = (int) config('identity.otp.request_window_minutes') * 60;

        RateLimiter::hit($identifierKey, $decaySeconds);
        RateLimiter::hit($ipKey, $decaySeconds);

        return ! $identifierLimited && ! $ipLimited;
    }
}
