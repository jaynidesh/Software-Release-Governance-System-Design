# Phase 2 Passwordless Identity and RBAC Design

**Status:** Proposed for user approval
**Phase:** 2 — Identity and RBAC
**Date:** 2026-09-10
**Depends on:** Phase 1 foundation and `2026-09-02-release-governance-design.md`

## 1. Decision record and supersession

This design implements Phase 2 as a Laravel modular-monolith capability covering users, passwordless authentication, privileged multi-factor authentication (MFA), session security, roles, permissions, and application-scoped role assignments.

The following approved decisions supersede conflicting statements in the original brief and the base architecture:

- There are no passwords, password hashes, password-reset tokens, password-recovery screens, or public registration routes.
- Email one-time password (OTP) is the primary authentication method for every user.
- A user exercising a privileged permission must complete email OTP and then a time-based one-time password (TOTP), with a one-time recovery code accepted only as a replacement for the TOTP step.
- Users are created only by administrators. Creation sends an activation invitation; the invitation never creates or authenticates an unknown user.
- The first administrator is created only through an interactive Artisan command. No default credentials or environment-seeded administrator exist.
- A minimal application identity is delivered in Phase 2 so application-scoped assignments use a real foreign key. Phase 3 extends application configuration.

References to local password authentication, Argon2id password hashing, rehash-on-login, and `password_reset_tokens` in `2026-09-02-release-governance-design.md` are replaced by this document. All other approved architecture and security constraints remain in force.

## 2. Goals and boundaries

Phase 2 must provide:

- an administrator-managed user lifecycle;
- activation through the same passwordless email OTP flow used for later logins;
- privileged TOTP enrollment, verification, recovery codes, reset, and recovery;
- inactivity, absolute, revocation, and privileged-reauthentication session controls;
- lockout and rate limiting with administrative unlock;
- canonical permissions, configurable roles, and global or application-scoped assignments;
- server-side authorization for every protected request;
- minimal administrator screens for users, roles, assignments, security actions, and application identities;
- append-only login and security events required before the general audit subsystem arrives in Phase 5;
- environment-driven operational defaults validated against mandatory security bounds; and
- an authentication-provider contract that can support SSO later without changing authorization or session semantics.

Phase 2 does not provide public sign-up, passwords, API tokens, social login, LDAP/Active Directory, SAML/OIDC, full application configuration, general notification templates, the transactional notification outbox, or the final hash-chained audit store. Those remain later-phase concerns.

## 3. Architecture

Identity is a first-class module with four internal areas:

```text
HTTP controllers and Form Requests
        |
        v
Application actions
  - user lifecycle
  - primary authentication
  - MFA lifecycle
  - session lifecycle
  - role and assignment management
        |
        +--> PrimaryAuthenticationProvider contract
        |      `--> EmailOtpAuthenticationProvider
        +--> OtpDelivery contract
        |      `--> Laravel mail notification
        +--> TotpVerifier contract
        |      `--> OTPHP adapter
        `--> AuthorizationService
               `--> Eloquent/MySQL role and scope resolution
```

Controllers remain thin: they validate and authorize input, invoke one application action, and produce a redirect or view. State transitions and multi-record mutations live in focused actions and execute in transactions. Contracts are used only at authentication, OTP delivery, TOTP, and authorization boundaries where replacement or isolated testing is valuable.

The primary-authentication contract exposes provider-neutral `begin` and `complete` operations with a purpose, request context, opaque challenge reference, and typed result. The current provider is `email_otp`; a future SSO provider must still return the same identity result and is not allowed to bypass user state, MFA, session, scope, or reauthentication checks.

TOTP calculation uses `spomky-labs/otphp` `^11.5`. Enrollment QR codes are rendered locally as SVG through `bacon/bacon-qr-code` `^3.1`; no external QR service receives the shared secret. Both packages must pass the locked Composer audit before merge and in CI.

## 4. Persistence model

All tables use MySQL 8.4/InnoDB, `utf8mb4`, unsigned bigint internal keys, ULID public identifiers where records appear in routes, and UTC microsecond timestamps. Identity/configuration rows are deactivated or soft-deleted rather than physically deleted. Challenge and event tables are never exposed through direct route identifiers.

### 4.1 Users and applications

`users` contains:

- `id`, unique `public_id`, nullable unique `employee_number`, `name`, and unique normalized `email`;
- `state`: `INVITED`, `ACTIVE`, `SUSPENDED`, or `DEACTIVATED`;
- `timezone`, `email_verified_at`, `invited_at`, `invitation_expires_at`, `activated_at`, and `last_login_at`;
- `failed_auth_attempts`, `failed_auth_window_started_at`, and `locked_until`;
- monotonically increasing `session_version`;
- microsecond timestamps and `deleted_at`.

Email is trimmed and case-folded before validation, lookup, and persistence. A case-insensitive database unique constraint is the final race-safe guard. There is no `password` or `remember_token` column.

`applications` is intentionally minimal in Phase 2:

- `id`, unique `public_id`, unique normalized `code`, unique `name`, `is_active`, and timestamps.

Administrators with `admin.applications` may list, create, rename, activate, and deactivate these identities. Deactivation prevents new scoped assignments and new business actions but retains historical assignments. Phase 3 adds description, criticality, modules, ownership, policies, and other configuration without replacing the Phase 2 identity or foreign keys.

### 4.2 Passwordless challenges and MFA

`auth_challenges` contains:

- `id`, unique random `public_id`, required `user_id`, and `purpose`: `ACTIVATION`, `LOGIN`, or `REAUTHENTICATION`;
- a code HMAC, expiry, failed-attempt count, `delivered_at`, `consumed_at`, and `invalidated_at`;
- request IP, bounded user agent, correlation ID, and timestamps.

The HMAC input binds the code to the challenge public ID, purpose, and user ID. It uses HMAC-SHA-256 with the dedicated `AUTH_OTP_PEPPER`, and comparison is constant-time. The plaintext code exists only in request memory and, when queued, an application-encrypted queue payload. It is never written to the challenge, logs, events, cache, session, or error output. A generated `open_slot` is `1` only while both consumption and invalidation are null and otherwise `NULL`; unique `(user_id, purpose, open_slot)` plus a user-row lock permits only one open challenge for that purpose.

`pending_authentications` represents the bounded state between successful primary email OTP and completion of a required TOTP, recovery-code, or enrollment step. It contains `id`, unique public ID, user, primary challenge, purpose, HMAC of the regenerated browser session ID, captured `session_version`, expiry, `completed_at`, `invalidated_at`, request context, and timestamps. The encrypted browser session contains only its opaque public ID. A generated nullable `active_slot`, using the same `1`-while-open pattern, and unique `(user_id, purpose, active_slot)` enforce at most one active pending authentication per user and purpose; replacement first invalidates the old row while holding the user lock.

`user_mfa_methods` contains one TOTP method per user: `id`, `user_id`, type, encrypted secret, `confirmed_at`, `rotated_at`, `disabled_at`, nullable `last_accepted_timestep`, and timestamps. The secret uses Laravel's encrypted cast backed by `APP_KEY`, is stored in a `TEXT` column, and is hidden from serialization. Verification locks the method and accepts only a candidate time-step strictly greater than `last_accepted_timestep`; the value can never move backward. This prevents same-step, out-of-order skew-window, and concurrent replay.

`user_recovery_codes` contains `id`, `user_mfa_method_id`, an HMAC of one recovery code, `used_at`, and `created_at`. Codes are individually generated with a cryptographically secure random source, shown once, and compared in constant time. Regeneration invalidates every unused prior code. Recovery codes are accepted only after successful primary email OTP and consume exactly once.

### 4.3 Authorization

`roles` contains `id`, unique `public_id`, unique code, name, description, `is_system`, `is_active`, timestamps, and `deleted_at`.

`permissions` contains `id`, unique canonical code, description, and `scope_type` (`GLOBAL` or `APPLICATION`). Permissions are application-owned seed data: administrators compose roles from them but cannot create, rename, or delete permission codes.

`role_permissions` has a unique `(role_id, permission_id)` pair.

`role_assignments` contains user, role, nullable application, assignment validity (`starts_at`, `ends_at`, `revoked_at`), assigning/revoking actors, and timestamps. A stored generated unsigned `scope_key` equals `COALESCE(application_id, 0)`, and `(user_id, role_id, scope_key)` is unique. This prevents duplicate global assignments despite MySQL's treatment of `NULL` in unique indexes. A revoked tuple is reactivated by updating its durable row; append-only security events preserve each change.

A global assignment grants its role's global permissions and grants its application permissions across every active application. An application assignment grants only that role's application permissions for the named active application; any global permissions in the same role are ignored at application scope. Global and application grants are additive. Explicit deny rules are not part of Phase 2.

### 4.4 Sessions and security events

Laravel's database `sessions` table remains the session payload store. `auth_sessions` adds one authenticated-session record with an independent unique `public_id` ULID and a unique raw `session_id`, but deliberately has no foreign key to `sessions`: Laravel assigns a regenerated ID before its database session handler persists the new payload at response termination. The row also contains `user_id`, `started_at`, `last_seen_at`, `absolute_expires_at`, `primary_authenticated_at`, nullable `mfa_authenticated_at`, nullable `reauthenticated_at`, the captured `user_session_version`, `revoked_at`, IP address, bounded user agent, and timestamps.

After login, MFA completion, or reauthentication, the action regenerates the Laravel session, obtains the new ID, and creates or rekeys `auth_sessions` before returning the response. A metadata-write failure aborts authentication. A later payload-write failure produces no usable authenticated browser session and may leave only inert metadata, which the scheduled cleanup removes. Explicit revocation resolves an authorized `auth_sessions.public_id`, verifies ownership or `admin.users`, and deletes both internal rows by server-side session ID; ordinary expiry cleanup removes orphans from either table. The raw Laravel session ID is hidden from serialization and is never rendered, accepted as request input, used in a route, or written to application logs/events. MySQL integration tests cover initial login, each regeneration, rollback, payload absence, explicit deletion, cross-user denial, secret-ID non-disclosure, and orphan cleanup.

`login_events` records a unique public ID, nullable known user, HMAC of the normalized attempted identifier, purpose, result code, IP, bounded user agent, correlation ID, and occurrence time.

`security_events` records a unique public ID, nullable actor, nullable subject user, event code, schema-versioned metadata JSON, IP, bounded user agent, correlation ID, and occurrence time.

Event models expose no update or delete operation. Phase 2 database permissions and application code are append-only for these tables. Phase 5 migrates them behind the general audit infrastructure and hash-chain controls without discarding history.

### 4.5 Migration from the Phase 1 skeleton

Committed Phase 1 migrations are not rewritten. Forward Phase 2 migrations add and backfill the new identity columns, create the Phase 2 tables and constraints, then remove `users.password`, `users.remember_token`, and `password_reset_tokens`. Existing sessions are cleared during this cutover. Existing skeleton users are set to `DEACTIVATED`, receive public IDs and a new `session_version`, and receive no role assignment or invitation automatically. An administrator must explicitly reactivate and invite any account worth retaining after bootstrap.

The development-only `Test User` seeder is removed. User factories become passwordless and expose explicit invited, active, suspended, deactivated, locked, privileged, and MFA-confirmed states for tests. The password-removal migration is intentionally data-lossy and is never rolled back in production; rollback documentation states that recreating empty password columns cannot recover old credentials. Production uses a backup and forward-fix migration strategy.

## 5. User and activation lifecycle

### 5.1 First administrator

`php artisan identity:bootstrap-admin` is interactive only. It asks for employee number when used, name, email, and timezone; it never asks for or prints a password, OTP, TOTP secret, or recovery code. Migrations and canonical authorization seeds must already exist.

After collecting and validating input, the command locks the Administrator role row inside a transaction, confirms that no non-deactivated user has a current global Administrator assignment, creates the invited user and global assignment, appends a security event, and commits. Concurrent bootstrap commands therefore cannot create two initial administrators. The activation invitation is dispatched after commit. The command refuses to create another bootstrap administrator once one exists; all later administrators are created through the web administration flow.

No administrator is created by `DatabaseSeeder`, `.env`, fixture credentials, or deployment scripts.

### 5.2 Administrator-managed users

An administrator with `admin.users` and fresh privileged reauthentication can:

- create an invited user without granting any role;
- edit name, employee number, timezone, and email;
- resend or revoke an invitation;
- suspend, reactivate, or deactivate a user;
- unlock a locked account;
- revoke one or all sessions; and
- reset the target's TOTP method and recovery codes.

Every role-assignment mutation, including assignments submitted on the user-creation screen, separately requires `admin.roles` and fresh privileged reauthentication. When one request creates a user and supplies initial assignments, both permissions are checked at the controller and action boundaries before the transaction starts; any failed scope or permission check rolls back the user, assignments, events, and invitation dispatch together. A user with only `admin.users` can create and manage identity data but cannot grant any role, global Administrator access, or other privileged permission to another account.

Creation commits the user and assignments before dispatching the activation notice. The invitation contains the application name and login URL but no bearer token or automatic-login link. Activation is completed by requesting and successfully verifying a purpose-bound email OTP. This keeps account creation closed while using one primary-authentication protocol.

Invitation validity is represented by `invitation_expires_at`. Resend invalidates outstanding activation challenges, advances the expiry, and sends a new notice. An expired or revoked invitation cannot start activation until an administrator resends it. For an ordinary user, successful email OTP atomically sets `email_verified_at`, `activated_at`, and `ACTIVE`. For a privileged user, email OTP sets `email_verified_at` and creates the pending enrollment state; `activated_at` and `ACTIVE` are set only when TOTP enrollment completes. Neither path creates an authenticated session before all required proof is complete.

Changing an active user's email requires fresh administrator reauthentication, invalidates all outstanding challenges and sessions, increments `session_version`, clears email verification, returns the user to `INVITED`, and sends a new invitation. Unknown email addresses can never create a row through an authentication endpoint.

Web administrators cannot change their own role assignments. An administrator also cannot change a role's permission set while that role is assigned to them. A different freshly reauthenticated administrator must perform either operation. The final effective administrator cannot be revoked, deactivated, or made ineffective; the invariant is checked under row locks.

An effective administrator is an `ACTIVE` user with a current global grant of both `admin.users` and `admin.roles`. Any global assignment that makes its holder an effective administrator must start immediately and cannot have `ends_at`; administrator loss is always an explicit mutation protected by the row-locked final-administrator invariant. The system Administrator role's `admin.` permission bundle is immutable, although administrators may create separate roles for other permission combinations.

If an administrator principal's invitation expires or they lose both TOTP and recovery codes, an interactive `php artisan identity:recover-admin` command is the only offline recovery path. An administrator principal is a non-suspended, non-deactivated user holding the global system Administrator role; this includes the initial invited principal before activation. The command locks the relevant role/assignment/user rows, asks for the target email, incident reference, reason, and exact confirmation phrase without accepting those values as command-line options, then invalidates the target's MFA, recovery codes, challenges, pending authentications, and sessions; increments `session_version`; renews activation eligibility when needed; appends a CLI recovery security event; and dispatches a notice after commit. It cannot create a user, grant a role, change an email, unsuspend a user, or target a non-administrator principal. The target must still control the registered email, prove email OTP, and enroll new TOTP. The production runbook requires controlled console access, a change/incident record, and post-use review for this break-glass command; normal peer-administrator recovery remains the preferred path.

## 6. Authentication flows

### 6.1 Begin email OTP

1. The guest submits a normalized email to the login form.
2. The normalized-email HMAC is limited to three requests per fifteen minutes, while the client IP uses the separate, higher shared-network ceiling of thirty requests in the same window. Merely submitting an address never increments the account lock counter.
3. The system always returns the same accepted response for unknown, invited-but-expired, suspended, deactivated, and locked identities.
4. For an eligible `INVITED` or `ACTIVE` user, the action invalidates prior unconsumed challenges of the same purpose, generates a cryptographically random numeric code, stores only its bound HMAC, and dispatches one delivery notification after commit.
5. The opaque challenge reference is stored in the encrypted browser session; the verify form accepts only the code. The email and user ID are not accepted back from the browser as authority.

OTP notifications implement `ShouldQueue` and `ShouldBeEncrypted` and use the configured high-priority security queue. The encrypted job contains the one generated code and challenge reference. Retries reuse that code, lock and re-check the challenge before delivery, and skip invalidated, consumed, or expired challenges. A retry never mints a second code. Queue or mail failures are logged and monitored but never change the generic browser response or reveal account eligibility.

### 6.2 Verify email OTP

Verification locks the challenge and user rows in one transaction. It rejects an absent, mismatched, undelivered, expired, consumed, invalidated, or purpose-mismatched challenge with the single message "The code is invalid or expired." A valid code marks the challenge consumed before proceeding; concurrent submissions cannot both succeed.

A wrong code increments the challenge count and the user's sliding-window authentication failure count. Email OTP, TOTP, and recovery-code failures share the approved account counter. Five failures within fifteen minutes invalidate outstanding challenges and lock the account for thirty minutes. Success resets the failure window only after the complete required authentication sequence succeeds. Administrative unlock clears the window, invalidates outstanding challenges, increments `session_version`, and records a security event.

After primary proof:

- an ordinary active user receives a regenerated authenticated session;
- an invited ordinary user is activated and receives that session;
- a privileged user with confirmed TOTP receives a regenerated anonymous session and a pending-authentication record before proceeding to the TOTP form;
- a privileged user without confirmed TOTP receives the same bounded pending state before proceeding to mandatory enrollment; and
- a suspended, deactivated, expired-invitation, or newly locked user receives no session.

The pending-authentication middleware requires the opaque reference in the encrypted session, a matching HMAC of the current regenerated session ID, unexpired and unconsumed database state, the captured current `session_version`, and an eligible current user. Only the exact next-step route and a CSRF-protected POST authentication-cancel route are reachable in this state. Direct endpoint access, a reference copied to another browser session, state or privilege changes, a new primary challenge, expiry, lockout, cancellation, or successful completion invalidates it. Completion locks and marks it once before calling `Auth::login()` and regenerating the session again. For invited privileged users, activation changes to `ACTIVE` only in this final transaction; abandonment leaves the user invited.

### 6.3 Privileged TOTP and recovery

Privilege is permission-driven, not role-name-driven. The mandatory baseline is:

- every permission whose code starts with `admin.`;
- `production.approve`;
- `signoff.production`; and
- `maker_checker.override.approve`.

`admin.*` is documentation shorthand for the explicit canonical `admin.` prefix; it is not a stored wildcard permission. Environment configuration may add privileged exact codes or prefixes but cannot remove the baseline.

At login, a user is privileged when any current effective assignment grants one of those permissions globally or for any active application. The check is repeated from current database state rather than trusted from an earlier session snapshot. At authorization time, privileged reauthentication is based on the specific permission being exercised in its effective scope.

TOTP enrollment is reachable only through a valid pending authentication. It creates an encrypted unconfirmed secret, renders a local QR code plus a manual setup key, and requires a current TOTP before confirmation. The setup secret is not displayed again. On confirmation, the system generates the configured set of recovery codes, displays them once, and requires the user to acknowledge storage before completing authentication. Abandoned unconfirmed methods are purged after their configured lifetime.

TOTP uses RFC 6238 with a 30-second period, six digits, SHA-1 for broad authenticator compatibility, and a configurable clock-skew window limited to zero or one adjacent interval. Under a method-row lock, the implementation accepts only a valid candidate time-step strictly greater than the stored step and atomically advances it. Recovery-code use consumes one row atomically, sends a security notice, and prompts regeneration when the remaining count is low.

When a role or role-permission edit newly gives an active user a privileged effective permission, all that user's sessions are invalidated and their `session_version` is incremented. Their next authentication must enroll or prove TOTP. Removing privilege never automatically disables a confirmed TOTP method. TOTP reset requires a different freshly reauthenticated administrator, revokes all sessions and recovery codes, increments `session_version`, and forces reenrollment on the next privileged login. There is no email-only downgrade path for privileged users.

### 6.4 Privileged reauthentication

A state-changing operation authorized by a privileged permission requires a `reauthenticated_at` value no older than ten minutes. The reauthentication flow starts only after an authenticated user explicitly requests it, sends an email OTP to the stored verified address, then requires confirmed TOTP or one recovery code. Completion regenerates the session ID, updates the session metadata, and returns only to an allow-listed intended route.

Successful email OTP during reauthentication regenerates the still-authenticated session and creates a purpose-bound pending-authentication row; it does not yet refresh `reauthenticated_at`. Normal non-privileged access may continue, but the requested privileged mutation remains denied. Completing TOTP or recovery proof consumes the pending row, regenerates the session again, and refreshes `mfa_authenticated_at` and `reauthenticated_at`. A successful privileged login sets both timestamps at session creation; an ordinary login leaves them null.

Viewing a list does not silently send an OTP. Read-only screens may be visible under their permission, but each privileged mutation is independently protected. Later phases apply the same middleware to production approval, production sign-off, and maker-checker override approval.

TOTP rotation, TOTP disable/reset, and recovery-code regeneration are intrinsically sensitive credential mutations and always require this full fresh email-OTP-plus-TOTP/recovery reauthentication, regardless of whether the user currently exercises a privileged business permission. A stolen authenticated session alone can never replace or weaken MFA credentials.

## 7. Authorization design

`AuthorizationService` is the authoritative API for `user + permission code + optional application`. It evaluates current user state, assignment validity, role state, permission membership, application activity, MFA readiness for privileged permissions, session validity, and privileged-reauthentication freshness when the operation requires it.

Laravel Gates expose canonical permission codes and delegate to this service. Policies use it after resolving records through application-scoped queries. Route middleware handles broad permission and reauthentication prerequisites, while the application action repeats authorization at the use-case boundary before mutation. Blade capability checks are usability controls only.

Global operations require a global permission grant. Application operations require either a current global assignment carrying that application permission or a current assignment for the same application. An assignment is current only when it is not revoked, its start has arrived, and its optional end has not passed. Inactive users, roles, or applications never authorize new work.

The canonical permission catalog is the catalog in section 8 of the base architecture, using `signoff.production` as the canonical spelling. The source brief's `production.signoff` spelling is an alias in documentation only and is never seeded. Phase 2 seeds all permission codes now so later phases do not need to change authorization identities.

The permission-to-scope mapping is authoritative and seeded exactly as follows:

| Scope | Canonical permission codes |
| --- | --- |
| `GLOBAL` | `admin.users`, `admin.roles`, `admin.applications`, `admin.workflow`, `admin.checklists`, `admin.maker_checker`, `admin.notifications`, `admin.settings` |
| `APPLICATION` | `dashboard.view`, `task.view`, `release.view`, `release.create`, `release.edit`, `release.assign`, `release.transition`, `release.hold`, `release.resume`, `release.cancel`, `release.close`, `feature.manage`, `development.update`, `development.complete`, `checklist.complete`, `checklist.configure`, `test.library.view`, `test.library.manage`, `test.scope.manage`, `test.assign`, `test.execute`, `test.complete`, `defect.create`, `defect.assign`, `defect.update`, `defect.resolve`, `defect.retest`, `defect.accept_risk`, `defect.defer`, `defect.close`, `signoff.dev`, `signoff.uat`, `signoff.production`, `production.readiness.review`, `production.approve`, `production.deploy`, `production.rollback`, `production.validate`, `maker_checker.override.request`, `maker_checker.override.approve`, `attachment.upload`, `attachment.download`, `report.view`, `report.export`, `audit.view` |

`dashboard.view` and `task.view` are aggregate-surface permissions: an application-scoped assignment opens the surface but queries return only applications for which the user has that grant; a global assignment opens the same surface across all active applications. Seed tests assert the scope of every canonical permission and fail on any unclassified or extra code.

The following system roles are seeded as non-deletable identities with configurable permission bundles, except that the Administrator role's explicit `admin.` bundle is mandatory and immutable:

| Role | Initial permission bundle |
| --- | --- |
| Administrator | `dashboard.view`, `task.view`, `report.view`, `report.export`, `audit.view`, `admin.users`, `admin.roles`, `admin.applications`, `admin.workflow`, `admin.checklists`, `admin.maker_checker`, `admin.notifications`, `admin.settings` |
| Release Manager | `dashboard.view`, `task.view`, `release.view`, `release.create`, `release.edit`, `release.assign`, `release.transition`, `release.hold`, `release.resume`, `release.cancel`, `release.close`, `feature.manage`, `development.update`, `checklist.complete`, `test.library.view`, `test.scope.manage`, `test.assign`, `test.complete`, `defect.create`, `defect.assign`, `defect.update`, `defect.close`, `maker_checker.override.request`, `attachment.upload`, `attachment.download`, `report.view`, `report.export` |
| Developer | `dashboard.view`, `task.view`, `release.view`, `feature.manage`, `development.update`, `development.complete`, `checklist.complete`, `test.library.view`, `defect.create`, `defect.update`, `defect.resolve`, `attachment.upload`, `attachment.download` |
| Dev Tester | `dashboard.view`, `task.view`, `release.view`, `test.library.view`, `test.execute`, `defect.create`, `defect.update`, `defect.retest`, `attachment.upload`, `attachment.download` |
| UAT Tester | `dashboard.view`, `task.view`, `release.view`, `test.library.view`, `test.execute`, `defect.create`, `defect.update`, `defect.retest`, `attachment.upload`, `attachment.download` |
| Production Tester | `dashboard.view`, `task.view`, `release.view`, `test.execute`, `defect.create`, `defect.update`, `defect.retest`, `production.validate`, `attachment.upload`, `attachment.download` |
| Business Approver | `dashboard.view`, `task.view`, `release.view`, `signoff.uat`, `signoff.production`, `attachment.upload`, `attachment.download` |
| Technical Approver | `dashboard.view`, `task.view`, `release.view`, `signoff.dev`, `production.readiness.review`, `production.approve`, `signoff.production`, `attachment.upload`, `attachment.download` |
| Application Owner | `dashboard.view`, `task.view`, `release.view`, `release.create`, `release.edit`, `release.assign`, `feature.manage`, `production.readiness.review`, `attachment.upload`, `attachment.download`, `report.view`, `report.export` |
| Deployment Engineer | `dashboard.view`, `task.view`, `release.view`, `production.deploy`, `production.rollback`, `attachment.upload`, `attachment.download` |
| Auditor | `dashboard.view`, `release.view`, `report.view`, `report.export`, `audit.view`, `attachment.download` |
| Viewer | `dashboard.view`, `release.view`, `report.view` |

Administrator deliberately has no business sign-off, approval, deployment, or override-approval permission by default. Possessing any permission establishes eligibility only; later maker-checker rules still enforce independence.

## 8. Session controls

- Session data uses the database driver and encrypted cookies/payload settings from Phase 1. "Remember me" is not offered.
- Successful primary authentication regenerates the session ID. Completing MFA or privileged reauthentication regenerates it again.
- Every authenticated request checks a default fifteen-minute inactivity limit, an eight-hour absolute limit, revocation, user state, and the captured `session_version` against the current user.
- Activity updates are server-side and rate-limited to avoid a database write on every asset or rapid polling request. Only authenticated application requests extend inactivity; health endpoints and background requests do not.
- Expired, revoked, stale-version, suspended, or deactivated sessions are invalidated server-side, logged out, and redirected to login with a generic reason.
- Logout invalidates the current server-side session and rotates the CSRF token. "Log out all sessions" increments `session_version` and removes all stored sessions for the user.
- Concurrent sessions are allowed by default and listed to the user with start time, last activity, IP, and normalized device description. The user may revoke another session.
- All browser mutations retain Laravel CSRF protection. Authentication responses use `Cache-Control: no-store` and never place OTPs or secrets in URLs.

## 9. Environment configuration and validation

Application code reads only `config('identity...')`; `env()` calls exist only in `config/identity.php`. `.env.example` documents blank secrets and defaults, while `.env.testing.example` contains only deterministic, explicitly non-production test values.

| Environment key | Default | Enforced production rule |
| --- | ---: | --- |
| `AUTH_PROVIDER` | `email_otp` | Must be a registered provider; Phase 2 accepts only `email_otp` |
| `AUTH_OTP_CHANNEL` | `mail` | Must be a registered delivery channel; Phase 2 accepts only `mail` |
| `AUTH_OTP_PEPPER` | blank | Required; independent random secret of at least 32 bytes |
| `AUTH_OTP_DIGITS` | `6` | `6` or `8` |
| `AUTH_OTP_TTL_MINUTES` | `10` | `2..15` |
| `AUTH_OTP_MAX_ATTEMPTS` | `5` | `3..10` |
| `AUTH_OTP_REQUEST_LIMIT` | `3` | `1..10` |
| `AUTH_OTP_IP_REQUEST_LIMIT` | `30` | `10..300` |
| `AUTH_OTP_REQUEST_WINDOW_MINUTES` | `15` | `5..60` |
| `AUTH_OTP_RESEND_SECONDS` | `60` | `30..300` |
| `AUTH_CHALLENGE_RETENTION_HOURS` | `24` | `1..168` |
| `AUTH_INVITATION_TTL_DAYS` | `7` | `1..30` |
| `AUTH_LOCKOUT_ATTEMPTS` | `5` | `3..10` |
| `AUTH_LOCKOUT_WINDOW_MINUTES` | `15` | `5..60` |
| `AUTH_LOCKOUT_MINUTES` | `30` | `5..1440` |
| `AUTH_SESSION_INACTIVITY_MINUTES` | `15` | `5..60` |
| `AUTH_SESSION_ABSOLUTE_MINUTES` | `480` | `30..1440` and greater than inactivity |
| `AUTH_PRIVILEGED_REAUTH_MINUTES` | `10` | `1..30` and no greater than inactivity |
| `AUTH_TOTP_ISSUER` | `APP_NAME` | Non-empty, bounded display string |
| `AUTH_TOTP_WINDOW` | `1` | `0..1` |
| `AUTH_TOTP_RECOVERY_CODE_COUNT` | `10` | `8..16` |
| `AUTH_TOTP_RECOVERY_CODE_LENGTH` | `12` | `10..20` |
| `AUTH_UNCONFIRMED_MFA_TTL_MINUTES` | `30` | `5..120` |
| `AUTH_PENDING_AUTH_TTL_MINUTES` | `10` | `2..15` |
| `AUTH_ADDITIONAL_PRIVILEGED_PERMISSIONS` | blank | Comma-separated existing exact codes or trailing-dot prefixes; additive only |
| `AUTH_SECURITY_QUEUE` | `security` | Non-empty queue name |
| `AUTH_EVENT_RETENTION_DAYS` | `2555` | `365..3650` |

Cryptographic algorithms, purpose/user binding, one-time consumption, the mandatory privileged-permission baseline, MFA enforcement, CSRF, constant-time comparisons, encrypted secret storage, queue-payload encryption, session regeneration, and server-side expiration are not disableable settings.

The Phase 1 environment validator is extended with identity checks. Production startup and `environment:validate` fail closed for missing secrets, unsupported adapters, unsafe bounds, inconsistent session values, insecure session settings, or a database session/queue configuration that cannot support the selected controls. Changing `AUTH_OTP_PEPPER` invalidates outstanding OTPs and recovery codes; its rotation requires a controlled operational procedure. Changing `APP_KEY` invalidates encrypted MFA secrets and sessions and therefore requires forced reenrollment.

Laravel's existing `SESSION_LIFETIME` must equal `AUTH_SESSION_INACTIVITY_MINUTES`; the identity middleware is authoritative for inactivity and absolute expiration, and the validator rejects divergent values so cookie/session garbage collection cannot silently weaken or prematurely contradict the policy.

## 10. Routes and Bootstrap UI

Unauthenticated and pending-authentication routes:

- login email form, OTP request, OTP verification, pending TOTP/recovery verification, mandatory TOTP enrollment, and POST-only pending-authentication cancellation;
- no registration, password, password-reset, or automatic invitation-login route.

Authenticated self-service routes:

- POST-only logout; anonymous or GET logout is not routed, and CSRF remains mandatory;
- security overview, active-session list/revocation, reauthentication-protected recovery-code regeneration, and reauthentication-protected TOTP rotation;
- reauthentication begin/verify endpoints used by privileged mutations.

Administrator routes:

- resource-oriented users, roles, role assignments, and minimal applications;
- focused invitation resend/revoke, user suspension/reactivation/deactivation, unlock, session revocation, and MFA reset resources.

Form Requests own substantial validation and authorization. Implicit route binding uses public ULIDs; nested resources use scoped bindings. Forms use POST/PATCH/DELETE with CSRF. Lists have deterministic ordering and pagination.

Views extend the Phase 1 Bootstrap shell. Authentication pages use a focused unauthenticated layout, accessible labels, numeric input modes, paste-friendly OTP fields, countdown/resend feedback, and generic status messages. MFA setup provides QR and manual key alternatives plus a printable recovery-code view. Administrative pages show state, scope, effective dates, MFA readiness, lockout, and session status without ever rendering stored secrets or code hashes.

## 11. Events, errors, and privacy

Required login/security events include invitation creation/resend/revocation/activation; OTP request, delivery failure, verification failure, expiry, and consumption; authentication success/failure; lock/unlock; MFA enrollment/reset/rotation; recovery-code use/regeneration; session creation/revocation/expiry; user state/email change; role/permission/assignment change; rejected self-escalation; last-admin protection; privileged reauthentication; and unauthorized attempts.

Identifiers in public authentication responses are generic. Unknown, disabled, expired-invitation, and locked accounts receive the same request response. Verification failures do not distinguish mismatch, expiry, purpose, delivery, or invalidation. Administration screens may show accurate state only to authorized administrators.

The existing correlation ID is attached to every event and error. Logging redaction adds `otp`, `code`, `totp`, `recovery_code`, `mfa_secret`, `authorization`, `cookie`, and normalized email where needed. Unexpected failures use the Phase 1 sanitized exception flow. Mail transport and queue errors are reported with challenge IDs and correlation IDs, never codes or secrets.

Expired challenges and abandoned MFA enrollments are purged by a scheduled command. Login/security events remain for the configured retention period, with deletion disabled until the Phase 5 audit integration defines the controlled retention job.

## 12. Test strategy

Implementation is test-driven. Tests use Laravel time travel, notification/queue fakes, deterministic fake primary/TOTP providers, and MySQL integration tests for constraints, row locking, generated columns, and concurrency.

Required coverage includes:

- no public registration/password routes or password-bearing schema;
- administrator-only creation and activation invitation dispatch after commit;
- first-admin happy path, second-run refusal, concurrent bootstrap race, non-expiring effective-admin assignments, last-admin time travel, and the tightly constrained administrator-principal recovery command;
- normalized email uniqueness and email-change reactivation;
- generic anti-enumeration responses for unknown, invited-expired, suspended, deactivated, and locked users;
- OTP HMAC storage, purpose/user binding, resend invalidation, expiry, delivery failure, attempt exhaustion, and atomic one-time verification;
- account/IP rate limits, sliding failure window, lockout, successful reset, and administrator unlock;
- pending-auth direct access, cross-session copying, replay, expiry, cancellation, lockout, and invalidation after user-state/session-version changes;
- mandatory TOTP enrollment, encrypted secret, locally generated QR, strictly monotonic time-step acceptance, out-of-order skew-window rejection, concurrent replay rejection, and abandoned-enrollment cleanup;
- recovery-code hashing, single use under concurrency, regeneration invalidation, low-code warning, and no email-only privileged recovery;
- ordinary versus privileged login and permission-driven elevation after role changes;
- inactivity, absolute expiry, session rotation, Laravel payload/metadata persistence ordering, metadata-write rollback, payload absence, orphan cleanup, concurrent sessions, one/all revocation, and `session_version` invalidation;
- reauthentication success, expiry, safe return routes, CSRF, credential-rotation/regeneration step-up, and privileged mutation denial before proof;
- canonical permission seeds plus exact allow/deny assertions for every permission in every initial role;
- global versus application-scoped grants, inactive/expired/revoked assignments, cross-application isolation, and duplicate-global-assignment rejection;
- transactional initial-role authorization and denial of every role grant by an `admin.users`-only actor, including indirect global Administrator and privileged-role escalation;
- self-escalation and final-administrator protections under concurrency;
- user/role/application deactivation and immediate authorization/session effects;
- authenticated POST-only logout plus denial of GET, anonymous, and missing-CSRF logout attempts;
- public-ULID session revocation, cross-user revocation denial, and absence of raw Laravel session IDs from routes, forms, HTML, JSON, logs, and events;
- event completeness, correlation IDs, generic errors, redaction, and absence of plaintext OTP/MFA/recovery material from database rows, queue payload visibility, logs, sessions, and rendered HTML; and
- environment defaults, every invalid bound, mandatory baseline retention, cached configuration, locked dependency audit, formatting, level-8 static analysis, migrations, full PHPUnit suites, and the Vite production build.

Browser smoke tests cover invitation activation, ordinary login/logout, privileged enrollment/login, recovery-code login, administrator user creation, role assignment, and session revocation. The Phase 2 security review maps every approved control to code and test evidence and records residual risks, including email-account compromise, targeted lockout denial of service, mail/queue availability, and recovery-code custody.

## 13. Delivery slices and acceptance

Implementation is divided into independently implemented and reviewed slices:

1. identity configuration, passwordless schema migration, canonical permissions/roles, and minimal applications;
2. email OTP provider, encrypted delivery, activation, lockout, and events;
3. TOTP enrollment, recovery codes, privileged login, and MFA reset;
4. database session metadata, inactivity/absolute expiry, reauthentication, and revocation;
5. authorization service, Gates/policies, application scoping, and session invalidation on privilege changes;
6. first-admin command and administrator/self-service Bootstrap UI;
7. full security regression suite, documentation, dependency audits, and Phase 2 security review.

Phase 2 is accepted only when all slices are merged locally, migrations and canonical seeders rebuild a clean MySQL schema, the complete quality pipeline passes, the application can be run using the documented environment, no default credential exists, and an independent final review reports no unresolved correctness or security finding.
