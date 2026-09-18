<?php

declare(strict_types=1);

namespace App\Domain\Identity\Enums;

enum UserState: string
{
    case Invited = 'INVITED';
    case Active = 'ACTIVE';
    case Suspended = 'SUSPENDED';
    case Deactivated = 'DEACTIVATED';
}
