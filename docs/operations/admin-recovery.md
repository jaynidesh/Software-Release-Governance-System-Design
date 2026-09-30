# Controlled administrator recovery

Use this procedure only when an existing administrator principal cannot complete MFA or its invitation expired and normal recovery by a different freshly reauthenticated administrator is unavailable. It does not create a user, grant a role, change an email, reactivate a suspended/deactivated user, or bypass control of the registered mailbox.

## Preconditions and authorization

- Confirm the target already holds a current global system Administrator assignment and is not suspended or deactivated.
- Prefer a different administrator's web MFA-reset/invitation-resend workflow whenever possible.
- Open an incident or approved emergency change. Record the target, business owner, reason, UTC start time, operator, reviewer, and recovery window.
- Obtain two-person approval for controlled production console access. The operator and reviewer must not share credentials.
- Confirm the security queue and registered mail route are operational. Recovery still requires email OTP followed by new TOTP enrollment.
- Preserve relevant correlation IDs and security/login events. Do not request or record an OTP, TOTP secret, or recovery code.

## Execution

From one application node running the approved revision and production configuration:

```bash
php artisan environment:validate
php artisan identity:recover-admin
```

The command must remain interactive. Enter the existing registered email, incident reference, reason, and the exact displayed `RECOVER <email>` phrase. Never wrap the command with supplied answers, add options, or run it through a shared shell transcript that captures secrets.

Inside one locked transaction the command verifies administrator-principal eligibility; disables MFA and deletes recovery codes; invalidates challenges and pending authentication; removes all session metadata and payloads; increments `session_version`; returns the principal to invited state with renewed eligibility; and appends `identity.administrator.recovered` with the incident reference and reason. The encrypted notice is queued only after commit.

The command's success message is not proof of account recovery. Confirm the correlated security event and queued notice without inspecting its encrypted payload. If the command refuses the target, stop: do not alter rows or assignments manually. Resolve incorrect identity state or authorization through the normal peer-admin/governance process.

## User completion

1. The target opens the normal sign-in page from a trusted device; the notice contains no token.
2. The target requests and verifies an email OTP using the registered mailbox.
3. The target enrolls a new TOTP secret, stores the new recovery codes in an approved vault, acknowledges them, and reaches the application.
4. The target performs a fresh privileged reauthentication. A second administrator verifies the expected Administrator assignment and reviews active sessions.

## Closure and review

- Revoke unexpected sessions and confirm the old sessions, MFA method, and recovery codes cannot be used.
- Review `identity.administrator.recovered`, invitation/OTP, MFA-enrollment, authentication, and session-creation events by UTC time and correlation ID.
- Confirm the incident reference and reason contain no authentication secret.
- Remove emergency console access, rotate any temporary infrastructure credential, and attach the command result and event identifiers—not secret values—to the incident.
- Have the independent reviewer sign off on target eligibility, approvals, event continuity, new MFA custody, and access removal.

If registered-email control is lost, this Phase 2 procedure cannot recover the account. Escalate to the identity owner and security governance process; do not change the email or grant a replacement Administrator role directly in the database.
