# Phase 1 Security Review

**Review scope:** deployable Laravel foundation only

**Architecture baseline:** PHP 8.5, Laravel 13, MySQL 8.4, server-rendered Blade, local Bootstrap assets

**Out of scope:** release-management business features and their authorization, audit, evidence, and maker-checker controls

## Implemented controls and evidence

| Risk | Phase 1 control | Repository or command evidence |
|---|---|---|
| Secrets committed | Runtime `.env` files are ignored; checked-in examples contain names and local/test-only defaults | `git ls-files '*env*'`; `git check-ignore .env .env.testing` |
| Unsupported runtime | Composer locks PHP 8.5/Laravel 13 and CI selects PHP 8.5, Node 22, and MySQL 8.4 | `RuntimeRequirementsTest`; `composer validate --strict`; `.github/workflows/ci.yml` |
| Debug or configuration disclosure | Deployment validator rejects missing keys, non-UTC/non-MySQL settings, and insecure production debug, URL, or cookie settings | `EnvironmentValidatorTest`; `ProductionConfigurationTest`; `php artisan environment:validate` |
| Unexpected error disclosure | Debug-disabled errors are sanitized and responses carry a server-generated correlation ID | `ErrorHandlingTest`; `AssignCorrelationId`; `bootstrap/app.php` |
| Database mismatch or hidden migration drift | Runtime validation requires MySQL; CI and integration tests use MySQL; migrations declare UTC microsecond date-time columns | `MySqlConnectionTest`; `TimestampContractTest`; CI migration gate |
| Dependency unavailable | Separate liveness and database-readiness endpoints expose only stable status values | `HealthEndpointTest`; `/health`; `/ready` |
| Browser injection and framing | Local Vite/Bootstrap assets, a production-strict CSP, clickjacking/content-type/referrer/permissions headers, and production HTTPS HSTS | `SecurityHeadersTest`; `ApplicationShellTest`; `npm run build` |
| Sensitive log context | JSON stderr logging applies recursive sensitive-key redaction to Monolog context and extra data | `RedactSensitiveContextTest`; `UseJsonFormatter`; `config/logging.php` |
| Vulnerable locked packages | CI runs Composer and npm audits against lockfiles | `composer audit --locked`; `npm audit --audit-level=high`; `.github/workflows/ci.yml` |
| Unsafe production database changes | Operations separate the runtime and migration identities and prohibit production seeding | [Production foundation runbook](../runbooks/production-foundation.md) |

## Verification record

The Phase 1 acceptance gate is:

```bash
php artisan config:clear
CACHE_STORE=array php artisan optimize:clear
php artisan migrate:fresh --env=testing
php artisan environment:validate --env=testing
composer validate --strict
composer audit --locked
npm audit --audit-level=high
vendor/bin/pint --test
vendor/bin/phpstan analyse --memory-limit=1G
php artisan test
npm run build
```

The MySQL migration and test commands must target the dedicated test database. `migrate:fresh` is destructive. Registry-backed audits require network access and are repeated by CI.

## Residual risks and Phase 2 gates

- Authentication, application-scoped RBAC, MFA enrollment, account lockout, privileged reauthentication, and authorization policies are not implemented. No protected business route may be introduced until those controls exist and are tested.
- Release, test, defect, sign-off, deployment, evidence, notification, and audit records are not implemented. Consequently, seven-year retention, append-only history, maker-checker enforcement, WORM export, attachment scanning, and authorized downloads remain Phase 2 controls.
- Database least privilege and TLS are deployment-platform responsibilities in Phase 1. Effective grants and CA validation require environment-specific operational evidence.
- Redaction unit coverage proves recursive sensitive-key handling, while an end-to-end assertion of emitted stderr JSON across both context and extra data remains a test-hardening opportunity.
- Tailwind build packages remain locked although the application shell uses Bootstrap. They are audited in CI but should be removed in a focused dependency-cleanup change to reduce unused supply-chain surface.
- The local environment deliberately permits the configured Vite origin and inline styles for hot module replacement. Production and testing retain the strict same-origin policy; CI tests this separation.
- Package audit results are point-in-time evidence. CI must remain required on every promoted revision, and security advisories need an explicit triage process.

## Phase 1 decision

The foundation is suitable for continued development and controlled non-business deployment when the [production runbook](../runbooks/production-foundation.md) is followed. It is not approved to store or govern real release-management data until the Phase 2 controls above are implemented and reviewed.
