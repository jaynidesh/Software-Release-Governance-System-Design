<?php

declare(strict_types=1);

namespace App\Application\Identity\Reauthentication;

use App\Application\Identity\Mfa\VerifyPendingMfa;
use App\Models\PendingAuthentication;
use App\Services\Identity\SafeReturnRoute;
use Illuminate\Contracts\Session\Session;

final class CompleteReauthentication
{
    public function __construct(
        private readonly VerifyPendingMfa $verify,
        private readonly SafeReturnRoute $safeReturnRoute,
        private readonly Session $session,
    ) {}

    public function handle(
        PendingAuthentication $pending,
        string $code,
        ?string $ipAddress,
        ?string $userAgent,
        ?string $correlationId,
    ): string {
        $this->verify->handle($pending, $code, $ipAddress, $userAgent, $correlationId);
        $route = $this->safeReturnRoute->resolve(
            is_string($this->session->get('identity.reauthentication_return_route'))
                ? $this->session->get('identity.reauthentication_return_route')
                : null,
        );
        $this->session->forget('identity.reauthentication_return_route');

        return $route;
    }
}
