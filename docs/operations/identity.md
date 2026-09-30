# Identity operations

This runbook operates the Phase 2 passwordless identity and application-scoped authorization capability. Use it with the [production foundation runbook](../runbooks/production-foundation.md). All times stored by the application are UTC.

> **Acceptance status:** Phase 3 entry is pending. The automated Phase 2 gates pass, but the required real-browser smoke flows have not run because the browser runtime exposed no backend. See [Browser acceptance retry](#browser-acceptance-retry).

## Configuration

Run `php artisan environment:validate` after changing configuration and before building the configuration cache. Production requires MySQL, encrypted database sessions, the database queue, HTTPS, secure cookies, a non-empty `APP_KEY`, and an independent `AUTH_OTP_PEPPER` of at least 32 bytes.

| Area | Keys | Default / required relationship |
| --- | --- | --- |
| Primary proof | `AUTH_PROVIDER`, `AUTH_OTP_CHANNEL`, `AUTH_OTP_PEPPER` | `email_otp`, `mail`, and a platform-managed production secret independent of `APP_KEY` |
| OTP | `AUTH_OTP_DIGITS`, `AUTH_OTP_TTL_MINUTES`, `AUTH_OTP_MAX_ATTEMPTS`, `AUTH_OTP_RESEND_SECONDS` | 6 digits, 10 minutes, 5 attempts, 60-second resend delay |
| Request controls | `AUTH_OTP_REQUEST_LIMIT`, `AUTH_OTP_IP_REQUEST_LIMIT`, `AUTH_OTP_REQUEST_WINDOW_MINUTES` | 3 per identifier, 30 per IP, 15-minute window |
| Lockout | `AUTH_LOCKOUT_ATTEMPTS`, `AUTH_LOCKOUT_WINDOW_MINUTES`, `AUTH_LOCKOUT_MINUTES` | 5 attempts in 15 minutes, then 30 minutes |
| Sessions | `SESSION_DRIVER`, `SESSION_ENCRYPT`, `SESSION_LIFETIME`, `AUTH_SESSION_INACTIVITY_MINUTES`, `AUTH_SESSION_ABSOLUTE_MINUTES` | database, true, 15, 15, 480; session lifetime must equal inactivity and absolute must be greater |
| Step-up | `AUTH_PRIVILEGED_REAUTH_MINUTES`, `AUTH_ADDITIONAL_PRIVILEGED_PERMISSIONS` | 10 minutes; additions must be canonical exact codes or trailing-dot prefixes and cannot remove the mandatory set |
| TOTP | `AUTH_TOTP_ISSUER`, `AUTH_TOTP_WINDOW`, `AUTH_TOTP_RECOVERY_CODE_COUNT`, `AUTH_TOTP_RECOVERY_CODE_LENGTH`, `AUTH_UNCONFIRMED_MFA_TTL_MINUTES` | application name, window 1, 10 codes of length 12, 30-minute enrollment TTL |
| Transient state | `AUTH_PENDING_AUTH_TTL_MINUTES`, `AUTH_CHALLENGE_RETENTION_HOURS` | 10 minutes and 24 hours |
| Invitations | `AUTH_INVITATION_TTL_DAYS` | 7 days |
| Delivery | `QUEUE_CONNECTION`, `AUTH_SECURITY_QUEUE` | database connection and `security` queue |
| Records/UI | `AUTH_EVENT_RETENTION_DAYS`, `AUTH_ADMIN_PER_PAGE` | 2555 days and 15 rows; Phase 2 does not delete events |

See `.env.example` and `EnvironmentValidator` for the enforced bounds. Do not put production secrets in source control, command history, tickets, or logs. Configuration caching means runtime changes take effect only after `php artisan config:cache` and process restarts.

## Queue and mail

Identity notifications implement encrypted queued delivery and are dispatched only after the enclosing transaction commits. Run a dedicated worker for the security queue under the same revision and keys as the web application:

```bash
php artisan queue:work database --queue=security --sleep=3 --tries=3 --timeout=60
```

Keep the worker timeout below the connection's `retry_after`. Alert on `failed_jobs`, oldest security-queue age, delivery error rate, and worker absence. A queued OTP is revalidated immediately before mail delivery; expired, invalidated, or consumed challenges are not sent. Never replay or manually deserialize job payloads outside the approved application runtime.

## Scheduler and cleanup

Run Laravel's scheduler once per minute on every scheduler node:

```cron
* * * * * cd /srv/release-governance && php artisan schedule:run >> /dev/null 2>&1
```

The hourly `identity:cleanup` task uses `withoutOverlapping` and `onOneServer`. Every node must share a cache store with atomic locks; the production database cache satisfies this. Check registration with `php artisan schedule:list`.

The command removes data in dependency-safe order: stale invalid/completed/expired pending authentications, retained expired/consumed/invalidated challenges, abandoned unconfirmed MFA methods, old `auth_sessions` without a Laravel payload, then old authenticated Laravel payloads without metadata. Orphan cleanup observes a five-minute grace so response-termination payload writes and session rekeys can complete. Work is committed in bounded chunks and is safe to rerun:

```bash
php artisan identity:cleanup --chunk=500
```

The chunk option accepts 1–10000. Investigate nonzero counts that grow continually; check queue/database health, response failures, and scheduler overlap locks. The command intentionally never deletes `login_events` or `security_events`. `AUTH_EVENT_RETENTION_DAYS` documents the baseline only; controlled deletion is deferred to the Phase 5 audit integration.

## Bootstrap and invitations

After migrations and canonical authorization seeds, create the first administrator from a controlled interactive console:

```bash
php artisan identity:bootstrap-admin
```

The command accepts no credential options, creates one invited principal with a non-expiring global Administrator assignment, and refuses every later use. Preserve its security event. The invitation has no token or automatic-login URL: the recipient opens `/login`, enters the registered address, verifies the email OTP, enrolls TOTP, records recovery codes, and acknowledges custody before activation. Ordinary invited users activate after email OTP; privileged users are not active or authenticated until MFA enrollment completes.

Administrators create later users in the web UI. `admin.users` permits identity management; each initial or later role assignment separately requires `admin.roles`. Both require fresh privileged reauthentication. Resending an invitation invalidates outstanding activation state and renews expiry; revoking it expires eligibility without deleting the identity.

## Session operations

The Laravel `sessions` row contains the encrypted browser payload. `auth_sessions` contains server-only metadata and a public ULID; the raw session ID is hidden and never accepted in a route. A user can revoke one own session or all own sessions from `/security`; authorized administrators can revoke a target user's sessions. Revoke-all and security-sensitive identity changes increment `session_version`.

For a suspected compromise, prefer the web revocation action so the correlated security event is retained. If storage is inconsistent, capture database and application evidence first, then run `identity:cleanup`; do not manually delete only one side of an otherwise valid pair. A current session that lacks valid metadata is inert and is rejected on its next request.

## OTP pepper rotation

`AUTH_OTP_PEPPER` protects OTPs, normalized login-identifier hashes, pending-session bindings, and recovery-code hashes. There is no previous-pepper fallback. Rotation therefore invalidates every outstanding OTP, pending authentication, and recovery code.

1. Open an approved change and warn users that saved recovery codes will be replaced.
2. At the edge/load balancer, stop new authentication and invitation traffic while leaving the old application revision and old-pepper security workers running. Stop the scheduler so it cannot initiate overlapping operational work. Do **not** enable Laravel maintenance mode yet: ordinary `queue:work` pauses during maintenance unless `--force` is used.
3. Drain the `security` queue under the old revision and old pepper. Confirm the ready count, reserved count, and failed-job count are zero and the mail provider has accepted every intended delivery. Prefer already supervised workers; if an explicit drain worker is required, run `php artisan queue:work database --queue=security --stop-when-empty --tries=3 --timeout=60` without `--force` while web authentication remains edge-blocked.
4. Keep authentication blocked and wait at least the greater of `AUTH_OTP_TTL_MINUTES` and `AUTH_PENDING_AUTH_TTL_MINUTES`. Recheck that the security queue remains empty and no authentication request is in flight.
5. Enter Laravel maintenance mode, stop security workers, and install a new independent random secret of at least 32 bytes on every web, worker, and scheduler node. Rebuild the configuration cache before restarting any process. Never allow old- and new-pepper processes to serve concurrently.
6. Restart web processes, security workers, and the scheduler with the new pepper, then remove the edge authentication block and exit maintenance mode. Privileged users authenticate with TOTP and immediately regenerate recovery codes. Users without working TOTP require the normal different-administrator MFA reset or the controlled recovery procedure.
7. Monitor generic verification failures, lockouts, queue failures, and correlated events. Record the queue-empty evidence, process restart set, and completion time in the change.

Do not reuse `APP_KEY`, retain the old pepper in an ad hoc environment variable, or attempt to translate stored hashes.

## APP_KEY rotation

`APP_KEY` encrypts database session payloads, TOTP secrets, and queued notification payloads. Laravel supports comma-separated `APP_PREVIOUS_KEYS` for a staged transition, but old keys remain decryption authority and must be removed after every protected value and job has been replaced.

1. Open an incident/change record, back up the database, stop deployments, and inventory queued security jobs and confirmed MFA methods.
2. Drain workers under the old key. Enter maintenance mode and stop workers and the scheduler.
3. Generate a new key. Deploy it as `APP_KEY` on every node and put the former key in `APP_PREVIOUS_KEYS`. Clear/rebuild configuration caches and restart together.
4. Revoke all browser sessions. Require users to sign in again; privileged users rotate or reset TOTP so the encrypted secret is written under the new key. Confirm the security queue drains under the new key.
5. Only after all encrypted TOTP secrets have been re-enrolled/rotated and no old queued payload or session remains, remove the former key from `APP_PREVIOUS_KEYS`, rebuild caches, and restart all processes.
6. Verify ordinary and privileged sign-in, recovery-code regeneration, queue delivery, readiness, and sanitized error logs before closing the change.

If the old key is suspected compromised, do not retain it online for a long migration. Use a short maintenance window, revoke sessions, invalidate/reset MFA through controlled operations, discard queued encrypted jobs only with explicit incident approval, and remove the compromised key promptly.

## Monitoring and incident evidence

Alert on readiness failures, authentication failure/lockout rate changes, scheduler failures, cleanup count trends, security queue delay/failures, administrator recovery events, last-administrator protection events, and repeated unauthorized administration attempts. Preserve correlation IDs, `login_events`, `security_events`, mail-provider identifiers, deployment revision, and UTC timestamps. Never copy OTPs, TOTP secrets, recovery codes, cookies, raw Laravel session IDs, or decrypted job payloads into incident records.

## Browser acceptance retry

Phase 3 must not begin until an in-app Browser backend is attached and all required flows pass against an isolated MySQL/database-session/database-queue/mail-safe environment. Start the local server on a loopback URL, connect through the Browser skill, and record visible outcomes for every flow:

1. invitation activation;
2. ordinary login and POST logout;
3. privileged TOTP enrollment and later privileged login;
4. recovery-code login;
5. administrator user creation;
6. role assignment;
7. public-ULID session revocation; and
8. OTP resend countdown and delay feedback.

Confirm no page, route, browser-visible storage, or error reveals an internal numeric ID, raw Laravel session ID, email/identifier eligibility, OTP, TOTP secret after its one-time enrollment display, or recovery code after its one-time display. Append exact results and screenshots/evidence references to the Task 7 report, rerun the full automated pipeline, and only then change the Phase 3 entry status.
