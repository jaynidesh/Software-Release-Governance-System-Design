<?php

declare(strict_types=1);

namespace App\Domain\Identity\Enums;

enum MfaMethodType: string
{
    case Totp = 'TOTP';
}
