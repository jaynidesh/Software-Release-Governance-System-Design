<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Contracts\Identity\TotpVerifier;
use InvalidArgumentException;
use OTPHP\InternalClock;
use OTPHP\TOTP;

final class OtpPhpTotpVerifier implements TotpVerifier
{
    private const PERIOD = 30;

    private readonly int $window;

    public function __construct(?int $window = null)
    {
        $this->window = max(0, min(1, $window ?? (int) config('identity.totp.window')));
    }

    public function generateSecret(): string
    {
        return TOTP::generate(new InternalClock)->getSecret();
    }

    public function provisioningUri(string $secret, string $accountName): string
    {
        $totp = $this->totp($secret);
        $totp->setLabel($this->nonEmpty($accountName, 'account name'));
        $totp->setIssuer($this->nonEmpty((string) config('identity.totp.issuer'), 'issuer'));

        return $totp->getProvisioningUri();
    }

    public function verify(string $secret, string $code, ?int $timestamp = null): ?int
    {
        $timestamp ??= time();
        $currentStep = intdiv($timestamp, self::PERIOD);
        $totp = $this->totp($secret);

        for ($step = $currentStep - $this->window; $step <= $currentStep + $this->window; $step++) {
            if ($step >= 0 && hash_equals($totp->at($step * self::PERIOD), $code)) {
                return $step;
            }
        }

        return null;
    }

    private function totp(string $secret): TOTP
    {
        return TOTP::create($this->nonEmpty($secret, 'secret'), self::PERIOD, 'sha1', 6, clock: new InternalClock);
    }

    /** @return non-empty-string */
    private function nonEmpty(string $value, string $name): string
    {
        if ($value === '') {
            throw new InvalidArgumentException(sprintf('The TOTP %s cannot be empty.', $name));
        }

        return $value;
    }
}
