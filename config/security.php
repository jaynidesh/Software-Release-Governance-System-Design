<?php

declare(strict_types=1);

return [
    'content_security_policy' => "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self'; script-src 'self'",
    'hsts' => 'max-age=31536000; includeSubDomains',
];
