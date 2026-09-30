# Software Release Governance System

This repository contains the Laravel 13 modular-monolith foundation for the Software Release Governance System. Phase 1 establishes the supported runtime, MySQL-backed health and test paths, deployment validation, safe error handling, structured redacted logs, security headers, and a server-rendered Bootstrap shell. Phase 2 adds passwordless identity, privileged MFA, transactional sessions, public identifiers, and application-scoped RBAC.

The approved delivery plan assigns application configuration, versioned governance, audit and evidence, approvals, release records, testing, defects, production lifecycle, notifications, reporting, and final hardening to later phases 3–15. The current application must not be treated as a complete production-ready business system.

## Technical baseline

- PHP 8.5 and Composer 2.x
- Laravel 13 and PHPUnit 12
- MySQL 8.4 LTS
- Node.js 22 LTS and npm 10+
- Bootstrap 5.3 and Bootstrap Icons compiled locally with Vite

See the [local development runbook](docs/runbooks/local-development.md) for setup and startup instructions.

## Quality and acceptance commands

Prepare a dedicated MySQL test database and `.env.testing` before running the database-backed gates.

```bash
php artisan environment:validate
php artisan migrate:fresh --env=testing
composer quality
composer audit --locked
npm audit --audit-level=high
npm run build
```

`migrate:fresh` drops every table on the selected connection. Dependency audits require registry access.

CI runs validation, locked dependency audits, Pint, level-8 PHPStan, MySQL migrations, PHPUnit, and the Vite production build for every push and pull request.

## Project documentation

- [Approved architecture and system design](docs/superpowers/specs/2026-09-02-release-governance-design.md)
- [Phase 1 implementation plan](docs/superpowers/plans/2026-09-02-foundation.md)
- [Local development runbook](docs/runbooks/local-development.md)
- [Production foundation runbook](docs/runbooks/production-foundation.md)
- [Phase 1 security review](docs/security/phase-1-review.md)
- [Identity operations runbook](docs/operations/identity.md)
- [Controlled administrator recovery](docs/operations/admin-recovery.md)
- [Phase 2 identity security control matrix](docs/security/phase-2-control-matrix.md)
- [Continuous-integration workflow](.github/workflows/ci.yml)

Use the production runbook for environment requirements, database privilege separation, startup probes, logging, and rollback guidance.
