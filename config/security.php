<?php

declare(strict_types=1);

return [
    'content_security_policy' => "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self'; script-src 'self'",
    'vite_dev_server_origin' => env('VITE_DEV_SERVER_ORIGIN', 'http://localhost:5173'),
    'hsts' => 'max-age=31536000; includeSubDomains',
];
