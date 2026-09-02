# Phase 1 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a bootable, tested Laravel foundation with enforced runtime configuration, MySQL readiness checks, secure errors/logging, and the shared Bootstrap application shell.

**Architecture:** Scaffold Laravel 13 as the approved modular monolith and establish only the cross-cutting boundaries required by later domain phases. Health, configuration, middleware, logging, and presentation components remain focused and dependency-injected; no release-governance business tables or workflows are introduced in this phase.

**Tech Stack:** PHP 8.5, Composer 2.x, Laravel 13.x, MySQL 8.4 LTS/InnoDB, Blade, Bootstrap 5.3.8, Bootstrap Icons, Vite, PHPUnit 12, PHPStan/Larastan, and Laravel Pint.

**Spec:** `docs/superpowers/specs/2026-09-02-release-governance-design.md`

## Global Constraints

- PHP 8.5 with Composer 2.x.
- Laravel 13.x using Blade and server-rendered pages.
- MySQL 8.4 LTS, InnoDB, `utf8mb4`, foreign keys, and UTC `DATETIME(6)` timestamps.
- Bootstrap 5.3.x and Bootstrap Icons, with minimal framework-free JavaScript.
- PHPUnit 12 and Laravel test utilities.
- Laravel Pint and PHPStan/Larastan for formatting and static analysis.
- Vite only for compiling CSS and JavaScript assets; there is no SPA framework.
- Private filesystem/object storage behind authorized application downloads.
- Secrets never enter source control; `.env.example` contains only names and safe local defaults.
- Debug mode is disabled in production; users never receive stack traces, SQL, credentials, tokens, or environment values.
- The implementing runtime must be PHP 8.5 even though the current host CLI reports PHP 8.4.18.
- Phases 2-15 receive separate detailed plans. This plan stops after the independently deployable foundation passes acceptance.

---

## Planned file map

```text
app/Application/Foundation/{EnvironmentValidator,InvalidEnvironmentConfiguration}.php
app/Console/Commands/ValidateEnvironmentCommand.php
app/Contracts/Foundation/ReadinessCheck.php
app/Http/Controllers/Foundation/{LivenessController,ReadinessController,WelcomeController}.php
app/Http/Middleware/{AssignCorrelationId,SecurityHeaders}.php
app/Logging/{RedactSensitiveContext,UseJsonFormatter}.php
app/Services/Foundation/DatabaseReadinessCheck.php
app/Support/Exceptions/DomainRuleViolation.php
config/security.php
resources/{js/app.js,sass/app.scss,views/layouts/app.blade.php}
resources/views/components/{app-navbar,app-sidebar}.blade.php
resources/views/welcome.blade.php
tests/{Unit,Feature,Integration}/Foundation/
docs/runbooks/{local-development,production-foundation}.md
docs/security/phase-1-review.md
```

## Task 1: Scaffold Laravel and lock the runtime contract

**Files:**
- Create from Laravel skeleton: `artisan`, `bootstrap/app.php`, `composer.json`, `composer.lock`, `package.json`, `package-lock.json`, `phpunit.xml`, `public/index.php`, `config/*.php`, `database/migrations/*.php`, `resources/js/app.js`, `routes/web.php`, `tests/TestCase.php`
- Preserve: `docs/superpowers/specs/2026-09-02-release-governance-design.md`
- Modify: `composer.json`, `package.json`, `.env.example`
- Test: `tests/Feature/Foundation/RuntimeRequirementsTest.php`

**Interfaces:**
- Consumes: PHP 8.5 CLI, Composer 2.x, Node.js 22 LTS, npm 10+.
- Produces: Laravel 13 plus Composer scripts `test`, `analyse`, `format:check`, `quality` and npm scripts `dev`, `build`.

- [ ] **Step 1: Verify prerequisites**

```bash
php -r 'fwrite(STDOUT, PHP_VERSION . PHP_EOL); exit(PHP_VERSION_ID >= 80500 ? 0 : 1);'
composer --version
node --version
npm --version
mysql --version
```

Expected: PHP 8.5.x, Composer 2.x, Node 22.x, npm 10+, and access to a MySQL 8.4 LTS server. Provision dedicated `sbmtag` and `sbmtag_test` databases/users before Task 3. If PHP exits 1, switch to PHP 8.5; do not weaken `composer.json`.

- [ ] **Step 2: Scaffold without overwriting the design**

```bash
SBMTAG_SCAFFOLD_DIR="$(mktemp -d)"
composer create-project laravel/laravel:^13.0 "$SBMTAG_SCAFFOLD_DIR"
rsync -a --exclude='.git' --exclude='docs' "$SBMTAG_SCAFFOLD_DIR"/ ./
```

Expected: the Laravel skeleton is copied while `.git/` and `docs/` remain intact.

- [ ] **Step 3: Write the failing runtime-contract test**

Create `tests/Feature/Foundation/RuntimeRequirementsTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Tests\TestCase;

final class RuntimeRequirementsTest extends TestCase
{
    public function test_project_declares_the_approved_dependencies(): void
    {
        $composer = json_decode(file_get_contents(base_path('composer.json')), true, flags: JSON_THROW_ON_ERROR);
        $package = json_decode(file_get_contents(base_path('package.json')), true, flags: JSON_THROW_ON_ERROR);

        self::assertSame('^8.5', $composer['require']['php']);
        self::assertSame('^13.0', $composer['require']['laravel/framework']);
        self::assertSame('^5.3.8', $package['dependencies']['bootstrap']);
        self::assertArrayHasKey('bootstrap-icons', $package['dependencies']);
        self::assertArrayHasKey('@popperjs/core', $package['dependencies']);
    }
}
```

- [ ] **Step 4: Prove the test fails**

Run `php artisan test tests/Feature/Foundation/RuntimeRequirementsTest.php`.

Expected: FAIL because the stock skeleton has a lower PHP floor and lacks Bootstrap.

- [ ] **Step 5: Set dependencies and quality scripts**

Set these `composer.json` constraints and scripts, preserving the skeleton's remaining entries:

```json
{
  "require": {"php": "^8.5", "laravel/framework": "^13.0"},
  "require-dev": {
    "larastan/larastan": "^3.0",
    "laravel/pint": "^1.0",
    "phpstan/phpstan": "^2.0",
    "phpunit/phpunit": "^12.0"
  },
  "scripts": {
    "test": "@php artisan test",
    "analyse": "phpstan analyse --memory-limit=1G",
    "format:check": "pint --test",
    "quality": ["@format:check", "@analyse", "@test"]
  }
}
```

```bash
composer update --with-all-dependencies
npm install bootstrap@5.3.8 bootstrap-icons@^1.13 @popperjs/core@^2.11 sass@^1.90 --save
```

- [ ] **Step 6: Set non-secret environment defaults**

Ensure `.env.example` contains:

```dotenv
APP_NAME="Release Governance"
APP_ENV=local
APP_KEY=
APP_DEBUG=false
APP_URL=http://localhost
APP_TIMEZONE=UTC
LOG_CHANNEL=stderr
LOG_LEVEL=info
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=sbmtag
DB_USERNAME=sbmtag_app
DB_PASSWORD=
SESSION_DRIVER=database
SESSION_LIFETIME=15
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=false
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
QUEUE_CONNECTION=database
CACHE_STORE=database
FILESYSTEM_DISK=local
MAIL_MAILER=log
MAIL_FROM_ADDRESS="no-reply@example.invalid"
MAIL_FROM_NAME="${APP_NAME}"
```

- [ ] **Step 7: Verify and commit**

```bash
php artisan test tests/Feature/Foundation/RuntimeRequirementsTest.php
composer validate --strict
composer audit --locked
npm audit --audit-level=high
git add .env.example .gitignore app artisan bootstrap composer.json composer.lock config database package.json package-lock.json phpunit.xml public resources routes tests
git commit -m "chore: bootstrap Laravel foundation"
```

Expected: checks pass and the scaffold commit succeeds.

## Task 2: Enforce environment configuration

**Files:**
- Create: `app/Application/Foundation/InvalidEnvironmentConfiguration.php`
- Create: `app/Application/Foundation/EnvironmentValidator.php`
- Create: `app/Console/Commands/ValidateEnvironmentCommand.php`
- Modify: `config/app.php`
- Test: `tests/Unit/Foundation/EnvironmentValidatorTest.php`

**Interfaces:**
- Consumes: settings keys `environment`, `key`, `debug`, `url`, `timezone`, `database_connection`, `database_name`, `database_username`, `secure_cookie`.
- Produces: `EnvironmentValidator::validate(array $settings): void`, `InvalidEnvironmentConfiguration::$errors`, and Artisan `environment:validate`.

- [ ] **Step 1: Write failing validation tests**

Create `tests/Unit/Foundation/EnvironmentValidatorTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Unit\Foundation;

use App\Application\Foundation\EnvironmentValidator;
use App\Application\Foundation\InvalidEnvironmentConfiguration;
use PHPUnit\Framework\TestCase;

final class EnvironmentValidatorTest extends TestCase
{
    public function test_secure_production_settings_are_accepted(): void
    {
        (new EnvironmentValidator())->validate($this->secureSettings());
        self::assertTrue(true);
    }

    public function test_insecure_production_settings_are_rejected(): void
    {
        $settings = array_replace($this->secureSettings(), [
            'debug' => true,
            'url' => 'http://release.example.test',
            'database_connection' => 'sqlite',
            'secure_cookie' => false,
        ]);

        try {
            (new EnvironmentValidator())->validate($settings);
            self::fail('Expected invalid configuration.');
        } catch (InvalidEnvironmentConfiguration $exception) {
            self::assertSame([
                'DB_CONNECTION must be mysql.',
                'APP_DEBUG must be false in production.',
                'APP_URL must use HTTPS in production.',
                'SESSION_SECURE_COOKIE must be true in production.',
            ], $exception->errors);
        }
    }

    /** @return array<string, bool|string> */
    private function secureSettings(): array
    {
        return [
            'environment' => 'production', 'key' => 'base64:valid', 'debug' => false,
            'url' => 'https://release.example.test', 'timezone' => 'UTC',
            'database_connection' => 'mysql', 'database_name' => 'sbmtag',
            'database_username' => 'sbmtag_app', 'secure_cookie' => true,
        ];
    }
}
```

- [ ] **Step 2: Prove the tests fail**

Run `php artisan test tests/Unit/Foundation/EnvironmentValidatorTest.php`.

Expected: FAIL because both classes are absent.

- [ ] **Step 3: Implement the exception and validator**

Create `app/Application/Foundation/InvalidEnvironmentConfiguration.php`:

```php
<?php

declare(strict_types=1);

namespace App\Application\Foundation;

use RuntimeException;

final class InvalidEnvironmentConfiguration extends RuntimeException
{
    /** @param list<string> $errors */
    public function __construct(public readonly array $errors)
    {
        parent::__construct(implode(' ', $errors));
    }
}
```

Create `app/Application/Foundation/EnvironmentValidator.php`:

```php
<?php

declare(strict_types=1);

namespace App\Application\Foundation;

final class EnvironmentValidator
{
    /** @param array<string, bool|string|null> $settings */
    public function validate(array $settings): void
    {
        $errors = [];
        $production = ($settings['environment'] ?? null) === 'production';

        if (($settings['key'] ?? '') === '') $errors[] = 'APP_KEY is required.';
        if (($settings['timezone'] ?? null) !== 'UTC') $errors[] = 'APP_TIMEZONE must be UTC.';
        if (($settings['database_connection'] ?? null) !== 'mysql') $errors[] = 'DB_CONNECTION must be mysql.';
        if (($settings['database_name'] ?? '') === '') $errors[] = 'DB_DATABASE is required.';
        if (($settings['database_username'] ?? '') === '') $errors[] = 'DB_USERNAME is required.';
        if ($production && ($settings['debug'] ?? false) === true) $errors[] = 'APP_DEBUG must be false in production.';
        if ($production && ! str_starts_with((string) ($settings['url'] ?? ''), 'https://')) $errors[] = 'APP_URL must use HTTPS in production.';
        if ($production && ($settings['secure_cookie'] ?? false) !== true) $errors[] = 'SESSION_SECURE_COOKIE must be true in production.';

        if ($errors !== []) throw new InvalidEnvironmentConfiguration($errors);
    }
}
```

- [ ] **Step 4: Add the deployment command**

Create `app/Console/Commands/ValidateEnvironmentCommand.php`:

```php
<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Application\Foundation\EnvironmentValidator;
use App\Application\Foundation\InvalidEnvironmentConfiguration;
use Illuminate\Console\Command;

final class ValidateEnvironmentCommand extends Command
{
    protected $signature = 'environment:validate';
    protected $description = 'Validate deployment-critical application configuration';

    public function handle(EnvironmentValidator $validator): int
    {
        try {
            $validator->validate([
                'environment' => app()->environment(), 'key' => config('app.key'),
                'debug' => (bool) config('app.debug'), 'url' => config('app.url'),
                'timezone' => config('app.timezone'), 'database_connection' => config('database.default'),
                'database_name' => config('database.connections.mysql.database'),
                'database_username' => config('database.connections.mysql.username'),
                'secure_cookie' => (bool) config('session.secure'),
            ]);
        } catch (InvalidEnvironmentConfiguration $exception) {
            foreach ($exception->errors as $error) $this->error($error);
            return self::FAILURE;
        }

        $this->info('Environment configuration is valid.');
        return self::SUCCESS;
    }
}
```

Set `config/app.php` to `'timezone' => env('APP_TIMEZONE', 'UTC'),`.

- [ ] **Step 5: Verify and commit**

```bash
php artisan test tests/Unit/Foundation/EnvironmentValidatorTest.php
APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= DB_CONNECTION=mysql DB_DATABASE=sbmtag DB_USERNAME=sbmtag_app php artisan environment:validate
git add app/Application/Foundation app/Console/Commands/ValidateEnvironmentCommand.php config/app.php tests/Unit/Foundation/EnvironmentValidatorTest.php
git commit -m "feat: validate deployment environment"
```

Expected: tests pass; the command exits 0 for valid configuration and 1 with exact errors otherwise.

## Task 3: Add liveness and MySQL readiness endpoints

**Files:**
- Create: `app/Contracts/Foundation/ReadinessCheck.php`
- Create: `app/Services/Foundation/DatabaseReadinessCheck.php`
- Create: `app/Http/Controllers/Foundation/LivenessController.php`
- Create: `app/Http/Controllers/Foundation/ReadinessController.php`
- Modify: `app/Providers/AppServiceProvider.php`, `routes/web.php`
- Test: `tests/Feature/Foundation/HealthEndpointTest.php`
- Test: `tests/Integration/Foundation/MySqlConnectionTest.php`

**Interfaces:**
- Consumes: Laravel's configured database manager.
- Produces: `ReadinessCheck::check(): bool`, `GET /health`, and `GET /ready`.

- [ ] **Step 1: Write failing endpoint tests**

Create `tests/Feature/Foundation/HealthEndpointTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use App\Contracts\Foundation\ReadinessCheck;
use Tests\TestCase;

final class HealthEndpointTest extends TestCase
{
    public function test_liveness_returns_only_a_stable_status(): void
    {
        $this->getJson('/health')->assertOk()->assertExactJson(['status' => 'ok']);
    }

    public function test_readiness_is_ok_when_dependencies_are_available(): void
    {
        $this->app->bind(ReadinessCheck::class, fn (): ReadinessCheck => new class implements ReadinessCheck {
            public function check(): bool { return true; }
        });

        $this->getJson('/ready')->assertOk()->assertExactJson(['status' => 'ready']);
    }

    public function test_readiness_hides_dependency_details_when_unavailable(): void
    {
        $this->app->bind(ReadinessCheck::class, fn (): ReadinessCheck => new class implements ReadinessCheck {
            public function check(): bool { return false; }
        });

        $this->getJson('/ready')->assertStatus(503)->assertExactJson(['status' => 'unavailable']);
    }
}
```

Create `tests/Integration/Foundation/MySqlConnectionTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Integration\Foundation;

use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class MySqlConnectionTest extends TestCase
{
    public function test_suite_uses_mysql_and_can_query_it(): void
    {
        self::assertSame('mysql', config('database.default'));
        self::assertSame(1, (int) DB::selectOne('SELECT 1 AS ready')->ready);
    }
}
```

- [ ] **Step 2: Prove the endpoint tests fail**

Run `php artisan test tests/Feature/Foundation/HealthEndpointTest.php`.

Expected: FAIL because the contract, controllers, and routes are absent.

- [ ] **Step 3: Implement the database check**

Create `app/Contracts/Foundation/ReadinessCheck.php`:

```php
<?php

declare(strict_types=1);

namespace App\Contracts\Foundation;

interface ReadinessCheck
{
    public function check(): bool;
}
```

Create `app/Services/Foundation/DatabaseReadinessCheck.php`:

```php
<?php

declare(strict_types=1);

namespace App\Services\Foundation;

use App\Contracts\Foundation\ReadinessCheck;
use Illuminate\Database\DatabaseManager;
use Throwable;

final readonly class DatabaseReadinessCheck implements ReadinessCheck
{
    public function __construct(private DatabaseManager $database) {}

    public function check(): bool
    {
        try {
            return (int) $this->database->selectOne('SELECT 1 AS ready')->ready === 1;
        } catch (Throwable) {
            return false;
        }
    }
}
```

Bind the interface in `AppServiceProvider::register()`:

```php
$this->app->bind(
    \App\Contracts\Foundation\ReadinessCheck::class,
    \App\Services\Foundation\DatabaseReadinessCheck::class,
);
```

- [ ] **Step 4: Implement focused controllers and routes**

Create `LivenessController.php` in the planned namespace:

```php
<?php

declare(strict_types=1);

namespace App\Http\Controllers\Foundation;

use Illuminate\Http\JsonResponse;

final class LivenessController
{
    public function __invoke(): JsonResponse
    {
        return response()->json(['status' => 'ok']);
    }
}
```

Create `ReadinessController.php`:

```php
<?php

declare(strict_types=1);

namespace App\Http\Controllers\Foundation;

use App\Contracts\Foundation\ReadinessCheck;
use Illuminate\Http\JsonResponse;

final readonly class ReadinessController
{
    public function __construct(private ReadinessCheck $readiness) {}

    public function __invoke(): JsonResponse
    {
        $ready = $this->readiness->check();

        return response()->json(
            ['status' => $ready ? 'ready' : 'unavailable'],
            $ready ? 200 : 503,
        );
    }
}
```

Add to `routes/web.php`:

```php
use App\Http\Controllers\Foundation\LivenessController;
use App\Http\Controllers\Foundation\ReadinessController;

Route::get('/health', LivenessController::class)->name('health');
Route::get('/ready', ReadinessController::class)->name('ready');
```

- [ ] **Step 5: Verify MySQL and commit**

```bash
php artisan test tests/Feature/Foundation/HealthEndpointTest.php
php artisan test tests/Integration/Foundation/MySqlConnectionTest.php
php artisan migrate:fresh
git add app/Contracts/Foundation app/Services/Foundation app/Http/Controllers/Foundation app/Providers/AppServiceProvider.php routes/web.php tests/Feature/Foundation/HealthEndpointTest.php tests/Integration/Foundation/MySqlConnectionTest.php
git commit -m "feat: add application health checks"
```

Expected: endpoints pass, the integration test runs against MySQL, and framework migrations complete.

## Task 4: Establish correlation IDs and domain-safe errors

**Files:**
- Create: `app/Http/Middleware/AssignCorrelationId.php`
- Create: `app/Support/Exceptions/DomainRuleViolation.php`
- Modify: `bootstrap/app.php`
- Test: `tests/Feature/Foundation/ErrorHandlingTest.php`

**Interfaces:**
- Consumes: each HTTP request and later `DomainRuleViolation` exceptions.
- Produces: request attribute `correlation_id`, header `X-Correlation-ID`, shared log context, and 409 JSON `{message, code, failures, correlation_id}`.

- [ ] **Step 1: Write failing error-boundary tests**

Create `tests/Feature/Foundation/ErrorHandlingTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

final class ErrorHandlingTest extends TestCase
{
    public function test_every_response_has_a_server_generated_correlation_id(): void
    {
        $response = $this->withHeader('X-Correlation-ID', 'untrusted')->getJson('/health')->assertOk();
        $id = (string) $response->headers->get('X-Correlation-ID');

        self::assertNotSame('untrusted', $id);
        self::assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $id);
    }

    public function test_domain_failures_are_structured_without_internal_details(): void
    {
        Route::get('/_test/domain-error', static function (): never {
            throw new DomainRuleViolation('mandatory_checklist_incomplete', ['Complete DEV-01.']);
        });

        $this->getJson('/_test/domain-error')
            ->assertStatus(409)
            ->assertJsonPath('code', 'mandatory_checklist_incomplete')
            ->assertJsonPath('failures.0', 'Complete DEV-01.')
            ->assertJsonMissing(['trace', 'file', 'line']);
    }
}
```

- [ ] **Step 2: Prove the tests fail**

Run `php artisan test tests/Feature/Foundation/ErrorHandlingTest.php`.

Expected: FAIL because the middleware and exception are absent.

- [ ] **Step 3: Implement the exception contract**

Create `app/Support/Exceptions/DomainRuleViolation.php`:

```php
<?php

declare(strict_types=1);

namespace App\Support\Exceptions;

use RuntimeException;

final class DomainRuleViolation extends RuntimeException
{
    /** @param list<string> $failures */
    public function __construct(public readonly string $ruleCode, public readonly array $failures)
    {
        parent::__construct('The requested action is not permitted.');
    }
}
```

- [ ] **Step 4: Implement correlation middleware**

Create `app/Http/Middleware/AssignCorrelationId.php`:

```php
<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

final class AssignCorrelationId
{
    public function handle(Request $request, Closure $next): Response
    {
        $id = Str::uuid()->toString();
        $request->attributes->set('correlation_id', $id);
        Log::shareContext(['correlation_id' => $id]);
        $response = $next($request);
        $response->headers->set('X-Correlation-ID', $id);

        return $response;
    }
}
```

- [ ] **Step 5: Register middleware and rendering**

Merge into the existing configurators in `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(\App\Http\Middleware\AssignCorrelationId::class);
})
->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(function (DomainRuleViolation $exception, Request $request) {
        $payload = [
            'message' => $exception->getMessage(),
            'code' => $exception->ruleCode,
            'failures' => $exception->failures,
            'correlation_id' => $request->attributes->get('correlation_id'),
        ];

        return $request->expectsJson()
            ? response()->json($payload, 409)
            : back()->withErrors(['domain' => $exception->failures])->withInput();
    });

    $exceptions->respond(function (\Symfony\Component\HttpFoundation\Response $response) {
        $id = request()->attributes->get('correlation_id');
        if (is_string($id)) $response->headers->set('X-Correlation-ID', $id);

        return $response;
    });
})
```

Import `Exceptions`, `Middleware`, `Request`, and `DomainRuleViolation`. Retain the skeleton's routing and merge with existing callbacks.

- [ ] **Step 6: Verify and commit**

```bash
php artisan test tests/Feature/Foundation/ErrorHandlingTest.php
git add app/Http/Middleware/AssignCorrelationId.php app/Support/Exceptions/DomainRuleViolation.php bootstrap/app.php tests/Feature/Foundation/ErrorHandlingTest.php
git commit -m "feat: add safe application error boundary"
```

## Task 5: Add security headers and sensitive-log redaction

**Files:**
- Create: `config/security.php`
- Create: `app/Http/Middleware/SecurityHeaders.php`
- Create: `app/Logging/RedactSensitiveContext.php`
- Create: `app/Logging/UseJsonFormatter.php`
- Modify: `bootstrap/app.php`, `config/logging.php`
- Test: `tests/Feature/Foundation/SecurityHeadersTest.php`
- Test: `tests/Unit/Foundation/RedactSensitiveContextTest.php`

**Interfaces:**
- Consumes: HTTP responses and Monolog `LogRecord` context/extra arrays.
- Produces: deterministic response headers and `RedactSensitiveContext::__invoke(LogRecord $record): LogRecord`.

- [ ] **Step 1: Write failing tests**

Create `SecurityHeadersTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Tests\TestCase;

final class SecurityHeadersTest extends TestCase
{
    public function test_responses_include_the_security_baseline(): void
    {
        $this->get('/health')
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
            ->assertHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            ->assertHeader('Content-Security-Policy', config('security.content_security_policy'));
    }
}
```

Create `RedactSensitiveContextTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Unit\Foundation;

use App\Logging\RedactSensitiveContext;
use DateTimeImmutable;
use Monolog\Level;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;

final class RedactSensitiveContextTest extends TestCase
{
    public function test_sensitive_keys_are_redacted_at_every_depth(): void
    {
        $record = new LogRecord(new DateTimeImmutable(), 'test', Level::Info, 'request', [
            'email' => 'user@example.test', 'password' => 'secret',
            'headers' => ['Authorization' => 'Bearer secret'], 'smtp_token' => 'secret',
        ]);
        $redacted = (new RedactSensitiveContext())($record);

        self::assertSame('user@example.test', $redacted->context['email']);
        self::assertSame('[REDACTED]', $redacted->context['password']);
        self::assertSame('[REDACTED]', $redacted->context['headers']['Authorization']);
        self::assertSame('[REDACTED]', $redacted->context['smtp_token']);
    }
}
```

- [ ] **Step 2: Prove both tests fail**

Run `php artisan test tests/Feature/Foundation/SecurityHeadersTest.php tests/Unit/Foundation/RedactSensitiveContextTest.php`.

Expected: FAIL because the middleware and processor are absent.

- [ ] **Step 3: Implement header configuration and middleware**

Create `config/security.php`:

```php
<?php

declare(strict_types=1);

return [
    'content_security_policy' => "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self'; script-src 'self'",
    'hsts' => 'max-age=31536000; includeSubDomains',
];
```

Create `app/Http/Middleware/SecurityHeaders.php`:

```php
<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $response->headers->set('Content-Security-Policy', config('security.content_security_policy'));
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        if (app()->environment('production') && $request->isSecure()) {
            $response->headers->set('Strict-Transport-Security', config('security.hsts'));
        }

        return $response;
    }
}
```

Append `SecurityHeaders::class` after `AssignCorrelationId::class` in the existing middleware callback.

- [ ] **Step 4: Implement log redaction and JSON formatting**

Create `app/Logging/RedactSensitiveContext.php`:

```php
<?php

declare(strict_types=1);

namespace App\Logging;

use Monolog\LogRecord;

final class RedactSensitiveContext
{
    private const SENSITIVE_PARTS = ['authorization', 'cookie', 'password', 'secret', 'token', 'api_key', 'private_key'];

    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(context: $this->redact($record->context), extra: $this->redact($record->extra));
    }

    /** @param array<array-key, mixed> $values @return array<array-key, mixed> */
    private function redact(array $values): array
    {
        foreach ($values as $key => $value) {
            $normalized = strtolower((string) $key);
            $sensitive = array_any(self::SENSITIVE_PARTS, static fn (string $part): bool => str_contains($normalized, $part));
            $values[$key] = $sensitive ? '[REDACTED]' : (is_array($value) ? $this->redact($value) : $value);
        }

        return $values;
    }
}
```

Create `app/Logging/UseJsonFormatter.php`:

```php
<?php

declare(strict_types=1);

namespace App\Logging;

use Illuminate\Log\Logger;
use Monolog\Formatter\JsonFormatter;

final class UseJsonFormatter
{
    public function __invoke(Logger $logger): void
    {
        foreach ($logger->getLogger()->getHandlers() as $handler) {
            $handler->setFormatter(new JsonFormatter());
            $handler->pushProcessor(new RedactSensitiveContext());
        }
    }
}
```

Add to the `stderr` channel in `config/logging.php`:

```php
'tap' => [App\Logging\UseJsonFormatter::class],
```

- [ ] **Step 5: Verify and commit**

```bash
php artisan test tests/Feature/Foundation/SecurityHeadersTest.php tests/Unit/Foundation/RedactSensitiveContextTest.php
vendor/bin/phpstan analyse app/Http/Middleware app/Logging --memory-limit=1G
git add app/Http/Middleware/SecurityHeaders.php app/Logging bootstrap/app.php config/logging.php config/security.php tests/Feature/Foundation/SecurityHeadersTest.php tests/Unit/Foundation/RedactSensitiveContextTest.php
git commit -m "feat: secure responses and structured logs"
```

Expected: tests and static analysis pass.

## Task 6: Build the shared Bootstrap application shell

**Files:**
- Create: `app/Http/Controllers/Foundation/WelcomeController.php`
- Create: `resources/sass/app.scss`
- Modify: `resources/js/app.js`, `vite.config.js`, `routes/web.php`
- Create: `resources/views/layouts/app.blade.php`
- Create: `resources/views/components/app-navbar.blade.php`
- Create: `resources/views/components/app-sidebar.blade.php`
- Create: `resources/views/welcome.blade.php`
- Delete: `resources/css/app.css`
- Test: `tests/Feature/Foundation/ApplicationShellTest.php`

**Interfaces:**
- Consumes: local Bootstrap, Bootstrap Icons, Popper, and Vite assets.
- Produces: `layouts.app`, `<x-app-navbar />`, `<x-app-sidebar />`, and `GET /`.

- [ ] **Step 1: Write the failing shell test**

Create `tests/Feature/Foundation/ApplicationShellTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Tests\TestCase;

final class ApplicationShellTest extends TestCase
{
    public function test_foundation_page_renders_the_accessible_enterprise_shell(): void
    {
        $this->withoutVite();

        $this->get('/')
            ->assertOk()
            ->assertSee('Release Governance')
            ->assertSee('Software Release Governance, Testing & Sign-Off')
            ->assertSee('aria-label="Primary navigation"', escape: false)
            ->assertSee('Skip to main content');
    }
}
```

- [ ] **Step 2: Prove the test fails**

Run `php artisan test tests/Feature/Foundation/ApplicationShellTest.php`.

Expected: FAIL because the approved shell is absent.

- [ ] **Step 3: Configure local assets**

Create `resources/sass/app.scss`:

```scss
@import "bootstrap/scss/bootstrap";
@import "bootstrap-icons/font/bootstrap-icons.css";

:root { --app-sidebar-width: 16rem; }
body { min-height: 100vh; background: var(--bs-tertiary-bg); }
.app-sidebar { width: var(--app-sidebar-width); }
.skip-link { position: fixed; left: 1rem; top: -4rem; z-index: 2000; }
.skip-link:focus { top: 1rem; }
```

Replace `resources/js/app.js`:

```javascript
import * as bootstrap from 'bootstrap';

window.bootstrap = bootstrap;
```

Set the Laravel Vite plugin input in `vite.config.js`:

```javascript
input: ['resources/sass/app.scss', 'resources/js/app.js'],
```

- [ ] **Step 4: Implement layout components**

Create `resources/views/components/app-navbar.blade.php`:

```blade
<nav class="navbar navbar-expand-lg bg-primary navbar-dark shadow-sm">
    <div class="container-fluid">
        <a class="navbar-brand fw-semibold" href="{{ route('home') }}">
            <i class="bi bi-diagram-3 me-2" aria-hidden="true"></i>Release Governance
        </a>
        <span class="navbar-text text-white-50">Controlled delivery from Development to Production</span>
    </div>
</nav>
```

Create `resources/views/components/app-sidebar.blade.php`:

```blade
<aside class="app-sidebar bg-white border-end p-3" aria-label="Primary navigation">
    <nav>
        <ul class="nav nav-pills flex-column gap-1">
            <li class="nav-item">
                <a class="nav-link active" aria-current="page" href="{{ route('home') }}">
                    <i class="bi bi-house-door me-2" aria-hidden="true"></i>Home
                </a>
            </li>
            <li class="nav-item">
                <span class="nav-link disabled" aria-disabled="true">Sign in available in Phase 2</span>
            </li>
        </ul>
    </nav>
</aside>
```

Create `resources/views/layouts/app.blade.php`:

```blade
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'Release Governance')</title>
    @vite(['resources/sass/app.scss', 'resources/js/app.js'])
</head>
<body>
    <a class="skip-link btn btn-light" href="#main-content">Skip to main content</a>
    <x-app-navbar />
    <div class="d-flex min-vh-100">
        <x-app-sidebar />
        <main id="main-content" class="container-fluid p-4" tabindex="-1">
            @yield('content')
        </main>
    </div>
</body>
</html>
```

- [ ] **Step 5: Implement the page and route**

Create `WelcomeController.php`:

```php
<?php

declare(strict_types=1);

namespace App\Http\Controllers\Foundation;

use Illuminate\Contracts\View\View;

final class WelcomeController
{
    public function __invoke(): View
    {
        return view('welcome');
    }
}
```

Create `resources/views/welcome.blade.php`:

```blade
@extends('layouts.app')

@section('title', 'Foundation | Release Governance')

@section('content')
    <section class="card border-0 shadow-sm">
        <div class="card-body p-4">
            <span class="badge text-bg-primary mb-3">Foundation</span>
            <h1 class="h3">Software Release Governance, Testing &amp; Sign-Off</h1>
            <p class="text-body-secondary mb-0">Secure workflow, evidence, independent approvals, and complete release traceability.</p>
        </div>
    </section>
@endsection
```

Add `Route::get('/', WelcomeController::class)->name('home');` to `routes/web.php` and import the controller. Remove the stock welcome route.

- [ ] **Step 6: Verify and commit**

```bash
php artisan test tests/Feature/Foundation/ApplicationShellTest.php
npm run build
git add app/Http/Controllers/Foundation/WelcomeController.php package.json package-lock.json resources routes/web.php vite.config.js tests/Feature/Foundation/ApplicationShellTest.php
git commit -m "feat: add Bootstrap application shell"
```

Expected: test passes and Vite emits local versioned CSS, JS, icon fonts, and its manifest.

## Task 7: Add quality gates and MySQL CI

**Files:**
- Create: `phpstan.neon`, `.env.testing.example`, `.github/workflows/ci.yml`
- Modify: `config/database.php`, `config/queue.php`, `config/session.php`, `phpunit.xml`
- Test: `tests/Feature/Foundation/ProductionConfigurationTest.php`

**Interfaces:**
- Consumes: GitHub Actions, PHP 8.5, Node 22, MySQL 8.4.
- Produces: repeatable static analysis, formatting, tests, audits, migrations, and asset builds.

- [ ] **Step 1: Write a failing defaults test**

Create `tests/Feature/Foundation/ProductionConfigurationTest.php`:

```php
<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Tests\TestCase;

final class ProductionConfigurationTest extends TestCase
{
    public function test_security_relevant_defaults_are_explicit(): void
    {
        self::assertSame('UTC', config('app.timezone'));
        self::assertSame('mysql', config('database.default'));
        self::assertTrue((bool) config('session.encrypt'));
        self::assertTrue((bool) config('session.http_only'));
        self::assertSame('lax', config('session.same_site'));
        self::assertSame('database', config('queue.default'));
    }
}
```

- [ ] **Step 2: Prove the test fails, then align configuration**

Run `php artisan test tests/Feature/Foundation/ProductionConfigurationTest.php`.

Expected: FAIL if stock session encryption, database, or queue defaults remain. Set the corresponding defaults in `config/session.php`, `config/database.php`, and `config/queue.php` to the `.env.example` values.

Create `.env.testing.example`:

```dotenv
APP_NAME="Release Governance Test"
APP_ENV=testing
APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
APP_DEBUG=false
APP_URL=http://localhost
APP_TIMEZONE=UTC
LOG_CHANNEL=stderr
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=sbmtag_test
DB_USERNAME=sbmtag_test
DB_PASSWORD=test-secret
SESSION_DRIVER=database
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=false
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
QUEUE_CONNECTION=database
CACHE_STORE=database
MAIL_MAILER=array
```

Remove SQLite and in-memory database overrides from `phpunit.xml` so tests inherit MySQL settings.

- [ ] **Step 3: Configure level-8 analysis**

Create `phpstan.neon`:

```neon
includes:
    - vendor/larastan/larastan/extension.neon

parameters:
    level: 8
    paths:
        - app
        - routes
    tmpDir: storage/framework/cache/phpstan
```

- [ ] **Step 4: Add CI**

Create `.github/workflows/ci.yml`:

```yaml
name: CI
on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    services:
      mysql:
        image: mysql:8.4
        env:
          MYSQL_DATABASE: sbmtag_test
          MYSQL_USER: sbmtag_test
          MYSQL_PASSWORD: test-secret
          MYSQL_ROOT_PASSWORD: root-test-secret
        ports: ['3306:3306']
        options: >-
          --health-cmd="mysqladmin ping --silent"
          --health-interval=10s --health-timeout=5s --health-retries=10
    env:
      APP_ENV: testing
      APP_KEY: base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
      APP_DEBUG: false
      APP_URL: http://localhost
      APP_TIMEZONE: UTC
      DB_CONNECTION: mysql
      DB_HOST: 127.0.0.1
      DB_PORT: 3306
      DB_DATABASE: sbmtag_test
      DB_USERNAME: sbmtag_test
      DB_PASSWORD: test-secret
      SESSION_DRIVER: database
      SESSION_ENCRYPT: true
      QUEUE_CONNECTION: database
      CACHE_STORE: database
      MAIL_MAILER: array
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.5'
          extensions: mbstring, pdo_mysql, openssl
          coverage: none
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: npm
      - run: composer install --no-interaction --prefer-dist
      - run: npm ci
      - run: composer validate --strict
      - run: composer audit --locked
      - run: npm audit --audit-level=high
      - run: vendor/bin/pint --test
      - run: vendor/bin/phpstan analyse --memory-limit=1G
      - run: php artisan environment:validate
      - run: php artisan migrate:fresh --force
      - run: php artisan test
      - run: npm run build
```

- [ ] **Step 5: Verify and commit**

```bash
cp .env.testing.example .env.testing
php artisan migrate:fresh --env=testing
composer quality
composer audit --locked
npm audit --audit-level=high
npm run build
git add .env.testing.example .github/workflows/ci.yml composer.json composer.lock config/database.php config/queue.php config/session.php phpstan.neon phpunit.xml tests/Feature/Foundation/ProductionConfigurationTest.php
git commit -m "ci: enforce foundation quality gates"
```

Expected: formatting, analysis, tests, audits, migrations, and build pass; `.env.testing` stays ignored.

## Task 8: Document and verify the deployable foundation

**Files:**
- Create: `docs/runbooks/local-development.md`
- Create: `docs/runbooks/production-foundation.md`
- Create: `docs/security/phase-1-review.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: all Phase 1 commands and controls.
- Produces: repeatable local setup, production startup checks, security evidence, and the Phase 2 handoff.

- [ ] **Step 1: Write the local runbook**

Create `docs/runbooks/local-development.md`:

```markdown
# Local Development

Requirements: PHP 8.5 with mbstring, openssl and pdo_mysql; Composer 2.x; MySQL 8.4 LTS; Node 22 LTS; npm 10+.

1. Copy `.env.example` to `.env` and enter a dedicated local MySQL database and user.
2. Run `composer install` and `npm ci`.
3. Run `php artisan key:generate`.
4. Run `php artisan environment:validate`.
5. Run `php artisan migrate:fresh --seed`.
6. Run `composer quality` and `npm run build`.
7. Start `php artisan serve` and `php artisan queue:work --tries=3` in separate processes.

Never reuse production credentials locally and never commit `.env` or `.env.testing`.
```

- [ ] **Step 2: Write the production runbook**

Create `docs/runbooks/production-foundation.md`:

```markdown
# Production Foundation

1. Inject secrets through the deployment platform, not the release artifact.
2. Set production, non-debug, HTTPS, UTC and secure-cookie configuration.
3. Use a least-privilege MySQL runtime account over TLS.
4. Build with `composer install --no-dev --classmap-authoritative` and `npm ci && npm run build`.
5. Run `php artisan environment:validate` before serving traffic.
6. Run `php artisan migrate --force` with a separately authorized migration identity.
7. Cache configuration, routes and views.
8. Start supervised web and queue-worker processes.
9. Require `/health` and `/ready` to return 200 before routing traffic.
10. Ship JSON logs to protected centralized storage and alert on readiness or queue failures.

The runtime identity cannot grant privileges, alter migrations, or update/delete audit records.
```

- [ ] **Step 3: Record the security review**

Create `docs/security/phase-1-review.md`:

```markdown
# Phase 1 Security Review

| Risk | Control | Evidence |
|---|---|---|
| Secrets committed | Ignored runtime files and safe examples | `git ls-files '*env*'` |
| Debug disclosure | Production validator and sanitized errors | `EnvironmentValidatorTest`, `ErrorHandlingTest` |
| Database mismatch | MySQL-only config and MySQL CI | `MySqlConnectionTest`, CI migration |
| Browser injection | Local assets and security headers | `SecurityHeadersTest`, `npm run build` |
| Sensitive logging | Recursive redaction and JSON logs | `RedactSensitiveContextTest` |
| Trace loss | Server-generated correlation IDs | `ErrorHandlingTest` |
| Vulnerable packages | Locked audits | Composer and npm audit commands |

Authentication, RBAC, MFA enrollment, authorization policies, and account lockout are Phase 2. No protected business route exists before that phase.
```

- [ ] **Step 4: Replace the scaffold README**

Set `README.md` to identify the system; link the approved spec, this plan, both runbooks, and list:

```bash
php artisan environment:validate
php artisan migrate:fresh --env=testing
composer quality
composer audit --locked
npm audit --audit-level=high
npm run build
```

- [ ] **Step 5: Run the complete acceptance suite**

```bash
php artisan optimize:clear
php artisan migrate:fresh --env=testing
php artisan environment:validate --env=testing
composer validate --strict
composer audit --locked
npm audit --audit-level=high
vendor/bin/pint --test
vendor/bin/phpstan analyse --memory-limit=1G
php artisan test
npm run build
git status --short
```

Expected: every command exits 0; tests use MySQL; assets build; Git lists only Task 8 documentation.

- [ ] **Step 6: Commit the Phase 1 handoff**

```bash
git add README.md docs/runbooks docs/security/phase-1-review.md
git commit -m "docs: add foundation operations and security review"
git status --short
```

Expected: commit succeeds and the working tree is clean.

## Phase 1 completion criteria

- PHP 8.5 and Laravel 13 constraints are locked.
- Production-safe configuration is enforced.
- MySQL 8.4 connectivity and migrations pass in CI.
- Liveness and sanitized readiness endpoints work.
- Correlation IDs, safe domain errors, security headers, structured logs, and nested redaction pass tests.
- The local Bootstrap shell builds and passes accessibility-oriented smoke assertions.
- Audits, Pint, level-8 PHPStan, PHPUnit, migrations, and Vite all pass.
- Local/production runbooks and the security review are committed.
- No release-management functionality has been introduced prematurely.
