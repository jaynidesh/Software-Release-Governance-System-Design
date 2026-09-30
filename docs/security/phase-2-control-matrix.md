# Phase 2 identity security control matrix

This matrix maps the approved Phase 2 identity/RBAC controls to implementation and executable evidence. The Phase 2 gate does not introduce release-governance records or a second authorization model.

| Control | Implementation evidence | Test evidence |
| --- | --- | --- |
| Passwordless, closed enrollment | Password columns/routes removed; invitation lifecycle and email OTP provider | `PasswordlessSchemaTest`, `InvitationActivationTest`, `IdentityRouteContractTest` |
| Enumeration-resistant authentication | Generic begin/verify messages; normalized identifiers represented as HMACs in login events | `AuthenticationPrivacyTest`, `EmailOtpAuthenticationTest`, `IdentitySecurityRegressionTest` |
| OTP confidentiality and one-time use | Purpose/user/public-ID-bound HMAC, encrypted after-commit notification, delivery-time state check, row locks | `EmailOtpAuthenticationTest`, `OtpConcurrencyTest`, `IdentitySecurityRegressionTest` |
| Resend/abuse/lockout controls | Identifier and IP throttles, server-authoritative resend delay with accessible countdown, shared failure window | `EmailOtpAuthenticationTest`, `AccountLockoutTest`, browser smoke: OTP resend/countdown |
| CSRF and method safety | Web CSRF middleware; POST/PATCH/PUT/DELETE mutation routes; POST-only logout | `AuthenticationPrivacyTest`, `LogoutSecurityTest`, `IdentityRouteContractTest` |
| Pending authentication binding | Public reference plus session-ID HMAC, purpose/state/version/expiry checks and exact-next-step middleware | `PendingAuthenticationTest`, `TotpEnrollmentTest` |
| Privileged MFA | Mandatory TOTP for effective privileged permissions; encrypted secret; monotonic accepted timestep; local QR/manual alternative | `TotpEnrollmentTest`, `TotpReplayTest`, `IdentitySecurityRegressionTest` |
| Recovery-code custody | HMAC-only storage, one-time locked consumption, regeneration invalidation, low-count warning | `RecoveryCodeAuthenticationTest`, `RecoveryCodeConcurrencyTest` |
| Session fixation/expiry/revocation | Session regeneration, transactional `auth_sessions`, inactivity/absolute/version checks, public ULID revocation | `SessionSecurityTest`, `AuthSessionPersistenceTest`, `SessionRevocationTest`, `IdentityRouteContractTest` |
| Metadata/payload write ordering | Metadata must persist before authentication succeeds; five-minute orphan grace covers response payload and rekey writes | `SessionSecurityTest`, `SessionRevocationTest`, `CleanupIdentityArtifactsTest` |
| Response confidentiality | Authentication/credential responses use `no-store, private`; raw session ID and credential material hidden | `AuthenticationPrivacyTest`, `PrivilegedReauthenticationTest`, `IdentityRouteContractTest` |
| Canonical authorization | Seeded permission catalog and initial roles; deny unknown codes | `AuthorizationSeederTest`, `EloquentAuthorizationServiceTest` |
| Application scope isolation | Global/application scope rules, active applications, generated durable scope key | `AuthorizationBoundaryTest`, `ScopedRoleAssignmentLockingTest`, `IdentitySecurityRegressionTest`, `IdentityMySqlRegressionTest` |
| Fresh privileged authorization | Form request plus transactional action reauthorization and explicit reauthentication | `AuthorizationBoundaryTest`, administration feature tests |
| Self-escalation prevention | Actor cannot mutate own assignments or assigned role composition/state | `RoleAssignmentTest`, `RoleAdministrationTest`, `AdministratorConcurrencyTest`, `IdentitySecurityRegressionTest` |
| Final administrator continuity | Effective-admin definition, row locks/mutex, bounded grant rules, time-aware invariant | `FinalAdministratorProtectionTest`, `AdministratorConcurrencyTest`, `IdentitySecurityRegressionTest` |
| Durable bootstrap and break glass | One-time locked interactive bootstrap; constrained interactive recovery with incident context | `BootstrapAdministratorCommandTest`, `RecoverAdministratorCommandTest`, administrator recovery runbook |
| Public identifiers | ULID route binding for users, roles, applications, assignments, and sessions; raw/internal IDs not rendered or accepted | administration tests, `SessionRevocationTest`, `IdentityRouteContractTest` |
| Transactional notification boundary | Security notifications are encrypted, queued, and dispatched after commit; rollback discards delivery | `AuthenticationPrivacyTest`, `UserAdministrationTest`, `IdentitySecurityRegressionTest` |
| Secret non-disclosure/redaction | Hidden hashes/session IDs/secrets, encrypted casts/payloads, redacting log processor, generic sanitized errors | `AuthenticationPrivacyTest`, `StructuredLoggingTest`, `RedactSensitiveContextTest`, `IdentitySecurityRegressionTest` |
| Correlated security evidence | Server-generated correlation ID propagated to login/security events and responses; append-only models | `AuthenticationPrivacyTest`, `IdentitySecurityRegressionTest`, `PasswordlessSchemaTest` |
| Transient-data cleanup | Hourly bounded/idempotent command, dependency-safe order, one-server/overlap locks, event deletion disabled | `CleanupIdentityArtifactsTest`, scheduler inspection, identity operations runbook |
| MySQL concurrency/storage semantics | Generated open/active/scope slots, unique keys, row locks, transactional retries | all `tests/Integration/Identity`, especially `IdentityMySqlRegressionTest` |
| Deployment configuration | Validated ranges/relationships, independent pepper, MySQL/database session/queue requirements | `IdentityConfigurationTest`, `EnvironmentValidatorTest`, clean MySQL migration/seed gate |
| Supply-chain/build acceptance | Locked Composer audit, strict manifest validation, Pint, level-8 PHPStan, PHPUnit, Node 22 production build | Task 7 acceptance report and CI workflow |

## Event retention boundary

`login_events` and `security_events` are append-only through their application models. Phase 2 cleanup deliberately preserves them even after `AUTH_EVENT_RETENTION_DAYS`. Phase 5 must add controlled retention, database-enforced audit protections, immutable export where required, and monitoring before any event deletion is enabled.

## Residual risks and required treatment

- Email-account compromise can satisfy primary proof and invitation activation. Privileged actions still require TOTP, but ordinary accounts rely on mailbox security. Require strong mail-account controls and investigate mailbox compromise as an identity incident.
- Identifier-based failure counting can be abused for targeted lockout denial of service; IP limits can also group users behind shared networks. Monitor spikes, rate-limit upstream, and use administrator unlock only after investigation.
- Mail and queue outages prevent authentication or delay notices. Alert on queue age/failures and mail-provider health; do not bypass proof or switch to plaintext/synchronous secret delivery.
- Recovery codes are bearer secrets outside application control once displayed. Require approved vault/offline custody, never email or log them, and regenerate after suspected exposure.
- `APP_KEY` or OTP-pepper compromise has broad blast radius. Follow the staged rotation runbook; pepper rotation invalidates recovery codes, while APP_KEY rotation requires session revocation and MFA secret re-encryption/re-enrollment.
- A five-minute orphan grace accepts bounded inert metadata/payload residue after failures. Monitor cleanup counts and investigate sustained growth.
- Application append-only models do not replace database privilege separation or immutable external audit storage. Restrict production DB identities now; Phase 5 must complete audit hardening.
- `onOneServer` and overlap protection depend on every scheduler sharing a healthy atomic-lock cache. Monitor scheduler execution and lock-store availability.
- Offline administrator recovery depends on controlled console access and registered-email control. Two-person approval, post-use review, and infrastructure credential removal remain operational controls.
- TOTP permits the configured adjacent-step clock window. Keep hosts time-synchronized; monotonic replay protection rejects reuse but cannot correct badly skewed clocks.
