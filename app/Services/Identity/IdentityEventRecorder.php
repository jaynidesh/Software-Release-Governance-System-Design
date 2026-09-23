<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\LoginEvent;
use App\Models\SecurityEvent;
use App\Models\User;

final class IdentityEventRecorder
{
    public function __construct(private readonly OtpHasher $hasher) {}

    public function login(
        string $normalizedIdentifier,
        AuthenticationPurpose $purpose,
        string $resultCode,
        ?User $user,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): LoginEvent {
        return LoginEvent::query()->create([
            'user_id' => $user?->getKey(),
            'identifier_hmac' => $this->hasher->hashIdentifier($normalizedIdentifier),
            'purpose' => $purpose,
            'result_code' => $resultCode,
            'ip_address' => $ipAddress,
            'user_agent' => $this->boundedUserAgent($userAgent),
            'correlation_id' => $correlationId,
            'occurred_at' => now(),
        ]);
    }

    /** @param array<string, bool|int|string|null> $metadata */
    public function security(
        string $eventCode,
        ?User $actor,
        ?User $subject,
        array $metadata,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): SecurityEvent {
        return SecurityEvent::query()->create([
            'actor_id' => $actor?->getKey(),
            'subject_user_id' => $subject?->getKey(),
            'event_code' => $eventCode,
            'schema_version' => 1,
            'metadata' => $metadata,
            'ip_address' => $ipAddress,
            'user_agent' => $this->boundedUserAgent($userAgent),
            'correlation_id' => $correlationId,
            'occurred_at' => now(),
        ]);
    }

    private function boundedUserAgent(?string $userAgent): ?string
    {
        return $userAgent === null ? null : mb_substr($userAgent, 0, 500);
    }
}
