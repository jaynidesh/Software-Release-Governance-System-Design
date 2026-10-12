<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Notifications\Identity\EmailOtpNotification;
use App\Support\Exceptions\OtpDeliveryException;
use Illuminate\Mail\SentMessage;
use Illuminate\Notifications\Channels\MailChannel;
use Illuminate\Notifications\Notification;
use Throwable;

final class SafeOtpMailChannel extends MailChannel
{
    public function send($notifiable, Notification $notification): ?SentMessage
    {
        try {
            return parent::send($notifiable, $notification);
        } catch (Throwable $exception) {
            if (! $notification instanceof EmailOtpNotification) {
                throw $exception;
            }

            // NotificationFailed and the worker must receive only the sanitized exception.
            throw new OtpDeliveryException($exception::class);
        }
    }
}
