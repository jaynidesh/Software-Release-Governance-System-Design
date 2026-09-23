<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Models\AuthChallenge;
use App\Models\User;
use Psr\Log\LoggerInterface;
use Throwable;

final class OtpDeliveryFailureReporter
{
    public function __construct(
        private readonly IdentityEventRecorder $events,
        private readonly LoggerInterface $logger,
    ) {}

    public function report(
        User $user,
        AuthChallenge $challenge,
        string $channel,
        ?Throwable $exception,
    ): void {
        $this->events->security(
            'identity.otp.delivery_failed',
            null,
            $user,
            ['challenge_reference' => $challenge->public_id, 'channel' => $channel],
            $challenge->request_ip,
            $challenge->user_agent,
            $challenge->correlation_id,
        );
        $this->logger->error('OTP delivery failed.', [
            'challenge_id' => $challenge->public_id,
            'correlation_id' => $challenge->correlation_id,
            'channel' => $channel,
            'exception_type' => $exception === null ? null : $exception::class,
        ]);
    }
}
