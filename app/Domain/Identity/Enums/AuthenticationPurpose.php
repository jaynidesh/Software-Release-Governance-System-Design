<?php

declare(strict_types=1);

namespace App\Domain\Identity\Enums;

enum AuthenticationPurpose: string
{
    case Activation = 'ACTIVATION';
    case Login = 'LOGIN';
    case Reauthentication = 'REAUTHENTICATION';
}
