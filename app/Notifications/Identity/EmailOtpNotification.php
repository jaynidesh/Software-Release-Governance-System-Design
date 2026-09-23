<?php

declare(strict_types=1);

namespace App\Notifications\Identity;

use App\Domain\Identity\Enums\AuthenticationPurpose;
use App\Models\AuthChallenge;
use App\Models\SecurityEvent;
use App\Models\User;
use App\Services\Identity\OtpHasher;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\DB;

final class EmailOtpNotification extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public function __construct(
        public readonly string $challengeReference,
        public readonly string $code,
    ) {
        $this->onQueue((string) config('identity.security_queue'));
        $this->afterCommit();
    }

    /** @return list<string> */
    public function via(User $notifiable): array
    {
        return ['mail'];
    }

    public function shouldSend(User $notifiable, string $channel): bool
    {
        return DB::transaction(function () use ($notifiable): bool {
            $challenge = AuthChallenge::query()
                ->where('public_id', $this->challengeReference)
                ->lockForUpdate()
                ->first();

            return $challenge !== null
                && $challenge->user_id === $notifiable->getKey()
                && $challenge->consumed_at === null
                && $challenge->invalidated_at === null
                && now()->isBefore($challenge->expires_at)
                && app(OtpHasher::class)->verify(
                    $this->code,
                    $challenge->public_id,
                    (int) $challenge->user_id,
                    AuthenticationPurpose::from((string) $challenge->getRawOriginal('purpose')),
                    $challenge->code_hmac,
                );
        });
    }

    public function toMail(User $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Your sign-in code')
            ->greeting('Hello '.$notifiable->name.',')
            ->line('Use this one-time code to continue:')
            ->line($this->code)
            ->line('This code expires soon. If you did not request it, you can ignore this email.');
    }

    public function afterSending(User $notifiable, string $channel, mixed $response): void
    {
        DB::transaction(function () use ($notifiable): void {
            $challenge = AuthChallenge::query()
                ->where('public_id', $this->challengeReference)
                ->lockForUpdate()
                ->first();

            if ($challenge === null || $challenge->user_id !== $notifiable->getKey()) {
                return;
            }

            $challenge->update(['delivered_at' => now()]);
            SecurityEvent::query()->create([
                'subject_user_id' => $notifiable->getKey(),
                'event_code' => 'identity.otp.delivered',
                'schema_version' => 1,
                'metadata' => ['challenge_reference' => $challenge->public_id],
                'ip_address' => $challenge->request_ip,
                'user_agent' => $challenge->user_agent,
                'correlation_id' => $challenge->correlation_id,
                'occurred_at' => now(),
            ]);
        });
    }
}
