<?php

declare(strict_types=1);

namespace App\Domain\Identity\Enums;

enum PermissionScope: string
{
    case Global = 'GLOBAL';
    case Application = 'APPLICATION';
}
