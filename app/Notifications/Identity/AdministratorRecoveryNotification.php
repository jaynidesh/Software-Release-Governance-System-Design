<?php

declare(strict_types=1);

namespace App\Notifications\Identity;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

final class AdministratorRecoveryNotification extends Notification implements ShouldBeEncrypted, ShouldQueue
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
            ->subject('Administrator recovery initiated')
            ->greeting('Hello '.$notifiable->name.'.')
            ->line('A controlled administrator recovery was initiated for your account.')
            ->line('Your sessions and multi-factor credentials were invalidated.')
            ->action('Restart activation', route('login'))
            ->line('Contact your security team immediately if this was unexpected.');
    }
}
