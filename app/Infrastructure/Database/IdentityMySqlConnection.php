<?php

declare(strict_types=1);

namespace App\Infrastructure\Database;

use Illuminate\Database\MySqlConnection;

final class IdentityMySqlConnection extends MySqlConnection
{
    use SanitizesSessionFailures;
}
