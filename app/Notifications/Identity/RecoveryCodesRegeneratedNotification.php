<?php

declare(strict_types=1);

namespace App\Notifications\Identity;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

final class RecoveryCodesRegeneratedNotification extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public function __construct()
    {
        $this->onQueue((string) config('identity.security_queue'));
        $this->afterCommit();
    }

    /** @return list<string> */
    public function via(User $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(User $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Your recovery codes were regenerated')
            ->greeting('Hello '.$notifiable->name.'.')
            ->line('A new set of recovery codes was generated and every previous code is now invalid.')
            ->line('Review your account security if you did not make this change.');
    }
}
