# Local Development

This runbook starts the Phase 1 Laravel foundation on a developer workstation. It does not provision shared infrastructure or production credentials.

## Requirements

- PHP 8.5 with `mbstring`, `openssl`, and `pdo_mysql`
- Composer 2.x
- MySQL 8.4 LTS
- Node.js 22 LTS (the project is verified with 22.22.3)
- npm 10 or newer

Verify the active tools before installing dependencies:

```bash
php --version
php -m
composer --version
mysql --version
node --version
npm --version
```

## First-time setup

1. Install locked PHP and JavaScript dependencies.

   ```bash
   composer install
   npm ci
   ```

2. Create local environment files only when they do not already exist.

   ```bash
   test -e .env || cp .env.example .env
   test -e .env.testing || cp .env.testing.example .env.testing
   ```

   Both runtime files are ignored by Git. Never overwrite an existing file without first preserving its local values.

3. In MySQL 8.4, create two empty databases and two non-production users:

   - `sbmtag` for interactive local development
   - `sbmtag_test` for automated tests

   Grant each user access only to its matching database. Put the local connection values in `.env` and the test connection values in `.env.testing`. Do not use MySQL `root`, reuse a production credential, or point either file at a shared database.

4. Generate a unique local application key, then validate both environments.

   ```bash
   php artisan key:generate
   php artisan environment:validate
   php artisan environment:validate --env=testing
   ```

   The checked-in key in `.env.testing.example` is intentionally public and is suitable only for isolated automated tests.

5. Rebuild the local and test schemas.

   ```bash
   php artisan migrate:fresh --seed
   php artisan migrate:fresh --env=testing
   ```

   `migrate:fresh` drops every table on the selected connection. Check the database name and user before running it. The local seed creates a development-only fixture user; never run the seeder in production.

6. Run the quality and asset gates.

   ```bash
   composer quality
   npm run build
   ```

## Run the application

Use separate terminals for the web process, Vite development server, and queue worker:

```bash
php artisan serve
```

```bash
npm run dev
```

```bash
php artisan queue:work --tries=3 --timeout=60
```

The default Vite origin is `http://localhost:5173`. If it changes, set the same valid HTTP(S) origin in `VITE_DEV_SERVER_ORIGIN`; Laravel and Vite consume that shared value. The relaxed development CSP applies only in the `local` environment.

Check the application and its dependency readiness:

```bash
curl --fail --silent --show-error http://127.0.0.1:8000/health
curl --fail --silent --show-error http://127.0.0.1:8000/ready
```

`/health` proves the web process is alive. `/ready` also verifies the database connection and returns HTTP 503 without database details when the dependency is unavailable.

## Before committing

Run the same local gates used by CI:

```bash
composer validate --strict
vendor/bin/pint --test
vendor/bin/phpstan analyse --memory-limit=1G
php artisan test
npm run build
```

Dependency audits require registry access:

```bash
composer audit --locked
npm audit --audit-level=high
```

Never commit `.env`, `.env.testing`, credentials, generated `public/build` assets, `vendor`, or `node_modules`.
