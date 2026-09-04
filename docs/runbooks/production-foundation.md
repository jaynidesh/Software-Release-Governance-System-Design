# Production Foundation

This runbook covers the deployment controls available in Phase 1. The approved delivery plan assigns identity and application-scoped RBAC to Phase 2, application and governance configuration to Phases 3–4, audit and evidence to Phase 5, approvals to Phase 6, and the remaining release, testing, defect, production-lifecycle, notification, reporting, and hardening capabilities to later phases.

## Platform prerequisites

- PHP 8.5 with `mbstring`, `openssl`, and `pdo_mysql`
- Composer 2.x
- MySQL 8.4 LTS
- Node.js 22 LTS and npm 10+ in the build environment
- A TLS-terminating web tier, a process supervisor, and protected centralized log storage

Use an immutable build artifact. Inject secrets through the deployment platform at runtime; do not add `.env` or `.env.testing` to the artifact.

## Required runtime configuration

Set at least these values through the deployment platform:

```dotenv
APP_ENV=production
APP_DEBUG=false
APP_URL=https://release-governance.example.com
APP_TIMEZONE=UTC
APP_KEY=<platform-managed-secret>

DB_CONNECTION=mysql
DB_HOST=<mysql-host>
DB_PORT=3306
DB_DATABASE=<application-database>
DB_USERNAME=<least-privilege-runtime-user>
DB_PASSWORD=<platform-managed-secret>
MYSQL_ATTR_SSL_CA=<path-to-trusted-ca>

SESSION_DRIVER=database
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
QUEUE_CONNECTION=database
CACHE_STORE=database

LOG_CHANNEL=stderr
LOG_LEVEL=info
```

Use a unique, randomly generated `APP_KEY`; rotating it invalidates encrypted application data and sessions. Terminate browser traffic with HTTPS and configure the platform so Laravel recognizes secure requests. MySQL transport must use TLS with a trusted CA.

## Database identities

Provision identities outside the application:

- The runtime identity can read and write only the application tables needed at runtime. It cannot grant privileges or alter the schema.
- A separately authorized migration identity may create or alter the application schema. Supply it only to the one-off migration job, then remove it from that job's environment.
- Future audit tables require database-enforced update/delete denial and mutation-rejecting triggers. Those tables and controls are not present in Phase 1.

Review effective grants before every production launch. Laravel configuration selects credentials but cannot enforce database privileges.

## Build the artifact

From a clean checkout of the approved revision:

```bash
composer install --no-dev --no-interaction --prefer-dist --classmap-authoritative
npm ci
npm run build
composer validate --strict
```

Ship the application, `vendor`, and `public/build` outputs. Do not ship `node_modules`, local environment files, test results, or development logs.

Run dependency audits in the controlled build pipeline, where registry access is available:

```bash
composer audit --locked
npm audit --audit-level=high
```

Do not promote an artifact with a high-or-critical npm finding or a Composer security advisory without a documented security decision.

## Deploy

1. Put the target out of rotation or deploy to a new inactive slot.
2. Inject the production runtime configuration and clear any cache inherited from another environment. The process-local array cache avoids querying the database-backed cache table before the first migration creates it.

   ```bash
   php artisan config:clear
   CACHE_STORE=array php artisan optimize:clear
   php artisan environment:validate
   ```

   Validation must report `Environment configuration is valid.` The command verifies only that `APP_KEY` is set, the timezone is UTC, MySQL is selected, the database name and username are non-empty, and production disables debug mode, uses an HTTPS application URL, and enables secure cookies. It does not connect to MySQL or verify the active database identity, effective grants, TLS or CA validation, session encryption, the HttpOnly flag, session driver, cache, queue, or logging configuration. Verify those controls separately through deployment configuration and operational checks.

3. Run migrations as a separately authorized one-off job. Never run the development seeder in production.

   ```bash
   php artisan migrate --force
   ```

4. Restore the least-privilege runtime database credentials, rerun the application configuration validator, independently verify the active database identity and effective grants, and build runtime caches.

   ```bash
   php artisan environment:validate
   php artisan config:cache
   php artisan route:cache
   php artisan view:cache
   ```

   A passing validator confirms only that the configured database username is non-empty; it does not authenticate that identity or inspect its grants.

5. Restart supervised web processes and queue workers on the new revision. A typical worker command is:

   ```bash
   php artisan queue:work --sleep=3 --tries=3 --timeout=60
   ```

   Keep the worker timeout below the configured database queue `retry_after` value (90 seconds by default). Use the process supervisor's stop timeout to let in-flight jobs exit cleanly.

6. Probe both endpoints before routing user traffic:

   ```bash
   curl --fail --silent --show-error https://release-governance.example.com/health
   curl --fail --silent --show-error https://release-governance.example.com/ready
   ```

   Both must return HTTP 200. `/health` checks the web process; `/ready` also checks MySQL. Do not route traffic when readiness returns HTTP 503.

7. Confirm that responses include the expected security and correlation headers, that JSON logs reach protected centralized storage, and that alerts cover readiness and queue failures.

## Rollback and recovery

- Keep the prior immutable application artifact available for application rollback.
- Do not automatically run `php artisan migrate:rollback` in production. Confirm schema compatibility and use an approved, tested database recovery plan; prefer forward-compatible and forward-fix migrations.
- After restoring an application artifact, clear and rebuild its configuration, route, and view caches, restart workers, and repeat the environment, liveness, and readiness checks.
- Preserve failed-deployment logs and the server-generated `X-Correlation-ID` values for investigation.

Phase 1 has no business release records or audit tables. Their append-only retention, evidence protection, maker-checker, and rollback governance controls must be implemented before business use.
