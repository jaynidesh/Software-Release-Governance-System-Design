# Passwordless Identity and RBAC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to execute this plan task-by-task.

**Goal:** Deliver Phase 2 passwordless email-OTP authentication, privileged TOTP, secure sessions, administrator-managed users, canonical RBAC, and application-scoped assignments so Phase 3 can extend real application identities safely.

**Architecture:** Add an `Identity` capability to the Laravel modular monolith. Thin controllers and Form Requests invoke transactional application actions; replaceable contracts isolate email OTP, delivery, TOTP, and authorization. MySQL is authoritative for challenges, pending authentication, roles, assignments, and authenticated-session metadata. Laravel Gates and policies delegate to a single scope-aware authorization service.

**Tech Stack:** PHP 8.5, Laravel 13.30, MySQL 8.4, PHPUnit 12, Larastan level 8, Bootstrap 5.3, `spomky-labs/otphp:^11.5`, `bacon/bacon-qr-code:^3.1`.

**Spec:** `docs/superpowers/specs/2026-09-10-passwordless-identity-rbac-design.md`

## Global Constraints

- Preserve all committed Phase 1 migrations; perform the passwordless conversion with forward migrations.
- Read environment values only in `config/identity.php`; all application code reads `config('identity...')`.
- Use public ULIDs for browser-facing identifiers. Raw Laravel session IDs, OTPs, TOTP secrets, and recovery codes never enter routes, logs, events, or rendered output except the one-time recovery-code result and initial TOTP setup view.
- Normalize email and application/role codes before validation and persistence. Database unique constraints remain the race-safe authority.
- Every multi-row mutation runs in a transaction, locks the controlling user/role rows, appends its security event, and dispatches notifications only after commit.
- A role or permission shown in Blade is never an authorization boundary. Form Requests authorize, and actions repeat authorization before mutations.
- Use `RefreshDatabase` for feature tests, MySQL-only integration tests for generated columns/locking/concurrency, `Notification::fake()` for delivery, and Laravel time travel for expiries.
- Every task follows red-green-refactor, runs its focused tests, runs `composer analyse`, and commits only its own files. Never stage the user-owned `prompt.txt`.

---

### Task 1: Identity configuration, schema, models, and canonical authorization seeds

**Files:**

- Modify: `composer.json`, `composer.lock`
- Create: `config/identity.php`
- Modify: `.env.example`, `.env.testing.example`
- Modify: `app/Application/Foundation/EnvironmentValidator.php`
- Modify: `app/Console/Commands/ValidateEnvironmentCommand.php`
- Create: `app/Domain/Identity/Enums/UserState.php`
- Create: `app/Domain/Identity/Enums/PermissionScope.php`
- Create: `app/Domain/Identity/Enums/AuthenticationPurpose.php`
- Create: `app/Domain/Identity/Enums/MfaMethodType.php`
- Create: `database/migrations/2026_09_14_000100_add_passwordless_identity_to_users.php`
- Create: `database/migrations/2026_09_14_000200_create_identity_authorization_tables.php`
- Create: `database/migrations/2026_09_14_000300_remove_password_authentication.php`
- Create: `app/Models/Application.php`, `app/Models/Role.php`, `app/Models/Permission.php`, `app/Models/RoleAssignment.php`
- Create: `app/Models/AuthChallenge.php`, `app/Models/PendingAuthentication.php`, `app/Models/UserMfaMethod.php`, `app/Models/UserRecoveryCode.php`, `app/Models/AuthSession.php`, `app/Models/LoginEvent.php`, `app/Models/SecurityEvent.php`
- Modify: `app/Models/User.php`, `database/factories/UserFactory.php`, `database/seeders/DatabaseSeeder.php`
- Create: `database/factories/ApplicationFactory.php`, `database/factories/RoleFactory.php`, `database/factories/PermissionFactory.php`, `database/factories/RoleAssignmentFactory.php`
- Create: `database/seeders/IdentityAuthorizationSeeder.php`
- Create: `app/Domain/Identity/AuthorizationCatalog.php`
- Create: `tests/Unit/Identity/IdentityConfigurationTest.php`, `tests/Feature/Identity/PasswordlessSchemaTest.php`, `tests/Feature/Identity/AuthorizationSeederTest.php`
- Create: `tests/Integration/Identity/GeneratedIdentityConstraintsTest.php`

**Interfaces:** Produces typed identity records, safe environment configuration, canonical permission/role catalog, and real `applications.id` foreign keys consumed by every later task and Phase 3. Does not expose an authentication route.

- [ ] Add failing configuration tests for all documented defaults, every range boundary, allowed adapters, mandatory privileged baseline, production OTP pepper requirements, and the session-lifetime equality invariant.
- [ ] Run `PATH=/opt/homebrew/opt/php/bin:$PATH php artisan test --testsuite=Unit --filter=IdentityConfigurationTest` and confirm the missing configuration/validation failures.
- [ ] Add `config/identity.php`; extend `EnvironmentValidator` and its command input mapping with typed identity settings and actionable validation messages.
- [ ] Add the OTPHP and local QR packages with Composer; run `composer audit --locked` and record zero advisories.
- [ ] Add failing schema/model tests asserting public ULIDs, user states and timestamps, absence of password columns/tables, hidden secret fields, encrypted casts, model relationships, and append-only event behavior.
- [ ] Implement the three forward migrations. Backfill existing users as `DEACTIVATED`, clear sessions, add generated nullable open/active slots and `scope_key`, then remove `password`, `remember_token`, and `password_reset_tokens`.
- [ ] Implement typed enums, Eloquent models, relationships, route keys, factories, and passwordless factory states.
- [ ] Add failing catalog tests that compare the complete permission-to-scope map and every exact initial system-role bundle from the spec, including Administrator exclusions.
- [ ] Implement immutable `AuthorizationCatalog`, idempotent `IdentityAuthorizationSeeder`, and an empty-by-default `DatabaseSeeder` that seeds authorization data but no user.
- [ ] Run focused SQLite-compatible tests, then run `tests/Integration/Identity/GeneratedIdentityConstraintsTest.php` against MySQL to prove open-challenge, active-pending, role-scope, and normalized uniqueness constraints.
- [ ] Run `PATH=/opt/homebrew/opt/php/bin:$PATH vendor/bin/pint --test`, `PATH=/opt/homebrew/opt/php/bin:$PATH composer analyse`, and focused tests.
- [ ] Commit as `feat(identity): add passwordless schema and authorization catalog`.

---

### Task 2: Scope-aware authorization and minimal application administration

**Files:**

- Create: `app/Contracts/Identity/AuthorizationService.php`
- Create: `app/Services/Identity/EloquentAuthorizationService.php`
- Create: `app/Application/Identity/Applications/CreateApplication.php`, `UpdateApplication.php`, `ChangeApplicationState.php`
- Create: `app/Http/Requests/Identity/Applications/StoreApplicationRequest.php`, `UpdateApplicationRequest.php`, `ChangeApplicationStateRequest.php`
- Create: `app/Http/Controllers/Identity/ApplicationController.php`, `ApplicationStateController.php`
- Create: `app/Policies/ApplicationPolicy.php`
- Modify: `app/Providers/AppServiceProvider.php`, `bootstrap/app.php`, `routes/web.php`
- Modify: `resources/views/components/app-navbar.blade.php`, `resources/views/components/app-sidebar.blade.php`
- Create: `resources/views/identity/applications/index.blade.php`, `create.blade.php`, `edit.blade.php`
- Create: `tests/Unit/Identity/EloquentAuthorizationServiceTest.php`
- Create: `tests/Feature/Identity/ApplicationAdministrationTest.php`, `AuthorizationBoundaryTest.php`

**Interfaces:** Consumes seeded roles/permissions/assignments. Produces `AuthorizationService::allows(User $user, string $permission, ?Application $application, bool $requiresFreshReauthentication): bool`, Laravel Gates for every canonical code, and administrator-managed application identities for Phase 3.

- [ ] Write failing authorization tests covering inactive users/roles/applications, future/expired/revoked assignments, global grants, same-application grants, cross-application denial, ignored global permissions on application-scoped assignments, privileged MFA readiness, and fresh-reauth requirements.
- [ ] Implement one eager-loaded Eloquent permission query path and register the contract plus canonical Gates in `AppServiceProvider`; enable development lazy-loading protection.
- [ ] Write failing feature tests for guest denial, `admin.applications` denial/allow, normalized unique codes, public route binding, deterministic pagination, deactivation effects, CSRF, and action-boundary reauthorization.
- [ ] Implement Form Requests, thin controllers, transactional actions, policy, scoped routes, and Bootstrap views. Deactivation must retain historical assignments but reject new assignments and new business authorization.
- [ ] Add navigation links guarded for usability while retaining server-side enforcement.
- [ ] Run focused unit/feature tests, static analysis, and formatter checks.
- [ ] Commit as `feat(identity): authorize scopes and manage applications`.

---

### Task 3: Email OTP, invitations, activation, lockout, and security events

**Files:**

- Create: `app/Contracts/Identity/PrimaryAuthenticationProvider.php`, `OtpDelivery.php`
- Create: `app/Domain/Identity/Data/BeginAuthentication.php`, `CompletedPrimaryAuthentication.php`
- Create: `app/Services/Identity/EmailOtpAuthenticationProvider.php`, `LaravelOtpDelivery.php`, `OtpHasher.php`, `AuthenticationThrottle.php`, `AccountLockout.php`, `IdentityEventRecorder.php`
- Create: `app/Notifications/Identity/EmailOtpNotification.php`, `ActivationInvitationNotification.php`
- Create: `app/Application/Identity/Authentication/BeginEmailOtp.php`, `VerifyEmailOtp.php`, `CancelPendingAuthentication.php`
- Create: `app/Application/Identity/Users/CreateInvitedUser.php`, `ResendInvitation.php`, `RevokeInvitation.php`, `UnlockUser.php`
- Create: `app/Http/Requests/Identity/Authentication/RequestOtpRequest.php`, `VerifyOtpRequest.php`
- Create: `app/Http/Controllers/Identity/Authentication/LoginController.php`, `OtpChallengeController.php`, `PendingAuthenticationCancellationController.php`
- Create: `resources/views/layouts/guest.blade.php`, `resources/views/identity/auth/login.blade.php`, `verify-otp.blade.php`
- Modify: `app/Logging/RedactSensitiveContext.php`, `app/Providers/AppServiceProvider.php`, `routes/web.php`
- Create: `tests/Unit/Identity/OtpHasherTest.php`, `AccountLockoutTest.php`
- Create: `tests/Feature/Identity/EmailOtpAuthenticationTest.php`, `InvitationActivationTest.php`, `AuthenticationPrivacyTest.php`
- Create: `tests/Integration/Identity/OtpConcurrencyTest.php`

**Interfaces:** Consumes passwordless users/configuration. Produces provider-neutral primary authentication, generic anti-enumeration HTTP behavior, purpose-bound challenges, invitation activation, shared account lockout, and append-only events. Privileged success yields only a pending-authentication reference for Task 4.

- [ ] Write unit tests proving HMAC binding to challenge/user/purpose, constant-time comparison behavior, sliding failure windows, and lockout reset.
- [ ] Write feature tests for generic begin responses across unknown and every ineligible user state, dual email/IP limits, resend timing, encrypted queued notification payloads, delivery after commit, and absence of plaintext codes in persistence/logs/sessions.
- [ ] Implement contracts, hash/rate/lock/event services, notifications, and transactional begin action with one open challenge per purpose.
- [ ] Write failing verification tests for undelivered, wrong, expired, consumed, invalidated, and purpose-mismatched challenges; attempt exhaustion; activation; ordinary login; privileged pending state; and replay.
- [ ] Implement verification using challenge and user row locks. Consume valid challenges once, share failure accounting across methods, activate only eligible ordinary users, and regenerate browser sessions at the boundaries in the spec.
- [ ] Implement invitation create/resend/revoke/unlock actions with after-commit notifications and complete login/security events.
- [ ] Implement guest views/routes with code-only verification input, `Cache-Control: no-store`, CSRF, and no public registration/password/reset/logout-GET routes.
- [ ] Run focused tests, MySQL concurrency tests, static analysis, formatting, and mail content/delivery assertions.
- [ ] Commit as `feat(identity): add passwordless email OTP activation`.

---

### Task 4: Privileged TOTP enrollment, recovery codes, and MFA lifecycle

**Files:**

- Create: `app/Contracts/Identity/TotpVerifier.php`
- Create: `app/Services/Identity/OtpPhpTotpVerifier.php`, `RecoveryCodeHasher.php`, `PrivilegedPermissionResolver.php`, `LocalTotpQrCode.php`
- Create: `app/Application/Identity/Mfa/BeginTotpEnrollment.php`, `ConfirmTotpEnrollment.php`, `VerifyPendingMfa.php`, `RegenerateRecoveryCodes.php`, `RotateTotp.php`, `ResetUserMfa.php`
- Create: `app/Http/Middleware/RequirePendingAuthentication.php`
- Create: `app/Http/Requests/Identity/Mfa/ConfirmEnrollmentRequest.php`, `VerifyMfaRequest.php`, `RegenerateRecoveryCodesRequest.php`
- Create: `app/Http/Controllers/Identity/Mfa/PendingMfaController.php`, `TotpEnrollmentController.php`, `RecoveryCodeController.php`
- Create: `resources/views/identity/mfa/verify.blade.php`, `enroll.blade.php`, `recovery-codes.blade.php`
- Modify: `app/Providers/AppServiceProvider.php`, `bootstrap/app.php`, `routes/web.php`
- Create: `tests/Unit/Identity/PrivilegedPermissionResolverTest.php`, `RecoveryCodeHasherTest.php`
- Create: `tests/Feature/Identity/TotpEnrollmentTest.php`, `PendingAuthenticationTest.php`, `RecoveryCodeAuthenticationTest.php`, `MfaResetTest.php`
- Create: `tests/Integration/Identity/TotpReplayTest.php`, `RecoveryCodeConcurrencyTest.php`

**Interfaces:** Consumes pending primary proof and current role grants. Produces confirmed encrypted TOTP methods, one-time recovery codes, completed privileged authentication, and MFA reset/rotation primitives used by admin and self-service flows.

- [ ] Write tests for the immutable privileged baseline plus additive configured exact codes/prefixes and current-database privilege evaluation.
- [ ] Implement the privilege resolver and OTPHP adapter with RFC 6238 defaults and a window no wider than one.
- [ ] Write failing pending-state middleware tests for direct access, copied-session HMAC mismatch, expiry, replay, cancellation, state/session-version changes, new primary challenges, and exact-next-route restrictions.
- [ ] Implement pending-state creation/validation/invalidation with regenerated-session HMAC binding and one active record per user/purpose.
- [ ] Write failing enrollment tests for local SVG/manual key, encrypted secret storage, no repeated secret display, confirmation before activation, recovery-code one-time display, and abandoned enrollment.
- [ ] Implement enrollment and recovery-code generation using cryptographically secure randomness; recovery hashes use the dedicated pepper and are never reversible.
- [ ] Write failing TOTP and recovery verification tests for shared lockout accounting, strict monotonic step acceptance, skew-window out-of-order denial, one-time consumption, low-code warning, and final privileged session creation.
- [ ] Implement row-locked verification, activation completion, recovery notices, rotation, and different-admin-only reset with session-version invalidation.
- [ ] Run focused suites plus MySQL replay/concurrency tests, dependency audit, analysis, and formatting.
- [ ] Commit as `feat(identity): enforce privileged TOTP authentication`.

---

### Task 5: Authenticated-session controls, revocation, and privileged reauthentication

**Files:**

- Create: `app/Services/Identity/AuthenticatedSessionManager.php`, `SessionActivityRecorder.php`, `SafeReturnRoute.php`
- Create: `app/Application/Identity/Sessions/CreateAuthenticatedSession.php`, `RevokeSession.php`, `RevokeAllSessions.php`, `RekeyAuthenticatedSession.php`
- Create: `app/Application/Identity/Reauthentication/BeginReauthentication.php`, `CompleteReauthentication.php`
- Create: `app/Http/Middleware/EnforceAuthenticatedSession.php`, `RequireFreshReauthentication.php`, `NoStoreAuthenticationResponse.php`
- Create: `app/Http/Controllers/Identity/Authentication/LogoutController.php`, `ReauthenticationController.php`, `SecurityOverviewController.php`, `SessionController.php`
- Create: `resources/views/identity/security/index.blade.php`, `resources/views/identity/auth/reauthenticate.blade.php`
- Modify: `bootstrap/app.php`, `routes/web.php`, `resources/views/components/app-navbar.blade.php`
- Create: `tests/Feature/Identity/SessionSecurityTest.php`, `SessionRevocationTest.php`, `PrivilegedReauthenticationTest.php`, `LogoutSecurityTest.php`
- Create: `tests/Integration/Identity/AuthSessionPersistenceTest.php`

**Interfaces:** Consumes successful ordinary/privileged authentication and current user/session versions. Produces authenticated session metadata, inactivity/absolute enforcement, public-ULID revocation, and freshness middleware consumed by all privileged Phase 2 and later-phase mutations.

- [ ] Write failing tests for login metadata creation, session regeneration/rekey after primary/MFA/reauth, metadata-write rollback, absent payload behavior, and no raw session ID disclosure.
- [ ] Implement the session manager with authenticated metadata creation before response termination and explicit rollback on metadata failure.
- [ ] Write failing middleware tests for inactivity, absolute expiry, revocation, user state, session-version mismatch, bounded activity writes, and exclusion of health/background requests.
- [ ] Implement enforcement and activity recording; expired sessions log out, invalidate server state, rotate CSRF, record a generic event, and redirect generically.
- [ ] Write failing revocation tests for own/other session, cross-user denial, administrator revocation, revoke-all version increment, payload deletion, public ULID binding, and orphan cleanup.
- [ ] Implement self-service overview and revocation actions without exposing raw IDs.
- [ ] Write failing reauthentication tests for explicit start only, email OTP then TOTP/recovery, interim ordinary access, safe allow-listed return routes, freshness expiry, and protected credential mutations.
- [ ] Implement reauthentication actions and middleware; only completed MFA refreshes `reauthenticated_at`.
- [ ] Implement authenticated POST-only logout with CSRF and add exhaustive route-method tests.
- [ ] Run focused feature/integration suites, analysis, and formatting.
- [ ] Commit as `feat(identity): enforce secure sessions and reauthentication`.

---

### Task 6: Administrator user, role, assignment, bootstrap, and recovery workflows

**Files:**

- Create: `app/Application/Identity/Users/UpdateUser.php`, `ChangeUserState.php`, `RevokeUserSessions.php`
- Create: `app/Application/Identity/Roles/CreateRole.php`, `UpdateRole.php`, `ChangeRoleState.php`, `SyncRolePermissions.php`
- Create: `app/Application/Identity/Assignments/AssignRole.php`, `RevokeRoleAssignment.php`
- Create: `app/Services/Identity/EffectiveAdministratorGuard.php`, `PrivilegeChangeInvalidator.php`
- Create: `app/Console/Commands/BootstrapAdministratorCommand.php`, `RecoverAdministratorCommand.php`
- Create: `app/Http/Requests/Identity/Users/StoreUserRequest.php`, `UpdateUserRequest.php`, `ChangeUserStateRequest.php`, `ResendInvitationRequest.php`, `UnlockUserRequest.php`, `ResetUserMfaRequest.php`
- Create: `app/Http/Requests/Identity/Roles/StoreRoleRequest.php`, `UpdateRoleRequest.php`, `SyncRolePermissionsRequest.php`, `ChangeRoleStateRequest.php`
- Create: `app/Http/Requests/Identity/Assignments/StoreRoleAssignmentRequest.php`, `RevokeRoleAssignmentRequest.php`
- Create: `app/Http/Controllers/Identity/UserController.php`, `UserStateController.php`, `InvitationController.php`, `UserSessionController.php`, `UserMfaController.php`, `RoleController.php`, `RolePermissionController.php`, `RoleAssignmentController.php`
- Create: `resources/views/identity/users/index.blade.php`, `create.blade.php`, `edit.blade.php`, `show.blade.php`
- Create: `resources/views/identity/roles/index.blade.php`, `create.blade.php`, `edit.blade.php`, `show.blade.php`
- Modify: `routes/web.php`, `resources/views/components/app-sidebar.blade.php`
- Create: `tests/Feature/Identity/UserAdministrationTest.php`, `RoleAdministrationTest.php`, `RoleAssignmentTest.php`, `BootstrapAdministratorCommandTest.php`, `RecoverAdministratorCommandTest.php`, `FinalAdministratorProtectionTest.php`
- Create: `tests/Integration/Identity/AdministratorConcurrencyTest.php`

**Interfaces:** Consumes authorization, session, invitation, and MFA actions. Produces the closed administrator-managed lifecycle, independently authorized role assignment, system-role protections, bootstrap, and break-glass recovery required for an operable deployment.

- [ ] Write failing tests proving `admin.users` cannot grant any role, every assignment mutation separately needs `admin.roles` and fresh proof, user+initial-assignment rollback is atomic, and action-level checks defeat controller bypass.
- [ ] Implement user and assignment actions under row locks with after-commit invitation delivery and privilege-change session invalidation.
- [ ] Write failing role tests for immutable canonical permissions, non-deletable system roles, immutable Administrator `admin.` bundle, self-assignment denial, and denial of editing a role assigned to the actor.
- [ ] Implement role composition and assignment administration with normalized codes, typed scope validation, current application requirements, and deterministic pagination.
- [ ] Write failing user lifecycle tests for edits, email reactivation, invite resend/revoke, suspend/reactivate/deactivate, unlock, session revoke, different-admin MFA reset, and complete security events.
- [ ] Implement the administrator Bootstrap UI and focused resource controllers/Form Requests; protect every mutation with fresh reauthentication.
- [ ] Write command tests for interactive-only input, first bootstrap, second-run refusal, no default credentials, global non-expiring Administrator assignment, recovery target constraints, exact confirmation, incident metadata, invalidation, and after-commit notice.
- [ ] Implement bootstrap and recovery commands with the row-locked effective-administrator invariant.
- [ ] Add MySQL concurrency and time-travel tests proving two bootstraps cannot succeed and the final effective administrator cannot be lost through state, assignment, role, or permission changes.
- [ ] Run focused suites, analysis, formatting, and audit.
- [ ] Commit as `feat(identity): add secure identity administration`.

---

### Task 7: Cleanup, complete security regression, documentation, and Phase 2 acceptance

**Files:**

- Create: `app/Console/Commands/CleanupIdentityArtifactsCommand.php`
- Modify: `routes/console.php`
- Create: `tests/Feature/Identity/CleanupIdentityArtifactsTest.php`, `IdentitySecurityRegressionTest.php`, `IdentityRouteContractTest.php`
- Create: `tests/Integration/Identity/IdentityMySqlRegressionTest.php`
- Create: `docs/operations/identity.md`, `docs/operations/admin-recovery.md`, `docs/security/phase-2-control-matrix.md`
- Modify: `README.md`

**Interfaces:** Consumes the completed Identity capability. Produces bounded cleanup, operating instructions, traceable security evidence, and the acceptance gate that permits Phase 3 work.

- [ ] Add failing cleanup tests for expired challenges, invalid pending records, unconfirmed MFA methods, orphan `auth_sessions`, and orphan Laravel session payloads; prove event retention is not yet deleted.
- [ ] Implement an idempotent chunked cleanup command and schedule it with overlap protection and one-server execution.
- [ ] Add the consolidated security regression named in the spec: enumeration resistance, CSRF, route methods, scope isolation, replay/concurrency, self-escalation, last-admin continuity, secret redaction/non-disclosure, and event correlation.
- [ ] Run clean MySQL migration and seeding from an empty database, then run all unit, feature, and MySQL integration tests.
- [ ] Write operator documentation for configuration, queues, scheduler, bootstrap, invitation activation, session cleanup, OTP-pepper rotation, APP_KEY rotation, and controlled administrator recovery.
- [ ] Write the Phase 2 control matrix mapping each approved control to implementation and test evidence; document residual risks from the design.
- [ ] Run `PATH=/opt/homebrew/opt/php/bin:$PATH composer validate --strict`, `composer audit --locked`, `vendor/bin/pint --test`, `composer analyse`, `php artisan test`, and `npm run build` with Node 22.
- [ ] Run browser smoke tests for invitation activation, ordinary login/logout, privileged enrollment/login, recovery login, user creation, role assignment, and public-ULID session revocation.
- [ ] Request independent code/security review, resolve every correctness/security finding with a reproducing test, and rerun the full pipeline.
- [ ] Commit as `docs(identity): complete phase two security acceptance`.

---

## Phase 3 Entry Gate

Phase 3 begins only after Task 7 passes. It extends the existing `applications` table and administration screens with modules, release types, system configuration, priorities, calendars, SLA policies, and versioned application policy records. It must not recreate application identities or introduce a second authorization model.
