<?php

declare(strict_types=1);

namespace App\Contracts\Foundation;

interface ReadinessCheck
{
    public function check(): bool;
}
