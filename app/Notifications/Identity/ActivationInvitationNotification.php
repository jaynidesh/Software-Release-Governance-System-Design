<?php

declare(strict_types=1);

namespace App\Notifications\Identity;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

final class ActivationInvitationNotification extends Notification implements ShouldBeEncrypted, ShouldQueue
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
            ->subject('Your Release Governance invitation')
            ->greeting('Hello '.$notifiable->name.',')
            ->line('You have been invited to Release Governance.')
            ->action('Open sign-in page', route('login'))
            ->line('Use your registered email address to continue.');
    }
}
