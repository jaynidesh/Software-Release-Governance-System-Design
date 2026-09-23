<?php

declare(strict_types=1);

namespace App\Services\Identity;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

final class LocalTotpQrCode
{
    public function render(string $provisioningUri): string
    {
        $renderer = new ImageRenderer(new RendererStyle(240, 2), new SvgImageBackEnd);

        return (new Writer($renderer))->writeString($provisioningUri);
    }
}
