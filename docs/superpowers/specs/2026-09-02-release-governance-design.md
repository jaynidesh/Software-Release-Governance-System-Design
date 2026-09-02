# Software Release Governance System Design

**Status:** Architecture approved; detailed design awaiting review  
**Date:** 2026-09-02  
**Architecture:** Laravel 13 modular monolith  

## 1. Purpose and boundaries

The system governs software releases from development through closure. It provides application-scoped access control, configurable workflow gates, reusable and release-specific tests, immutable execution history, defect and retest traceability, independent approvals, controlled production deployment and rollback, evidence management, notifications, reporting, and tamper-evident audit history.

The first version is a single-organization system managing multiple applications. It provides integration interfaces but does not initially connect to Jira, Azure DevOps, source-control systems, CI/CD systems, LDAP/SSO, ServiceNow, Teams, or monitoring products.

The design prioritizes security, traceability, segregation of duties, controlled progression, evidence, approval integrity, and auditability. Browser controls are usability aids; the server is authoritative for every permission, transition, checklist, testing, defect, sign-off, and maker-checker decision.

## 2. Approved technical baseline

- PHP 8.5 with Composer 2.x.
- Laravel 13.x using Blade and server-rendered pages.
- MySQL 8.4 LTS, InnoDB, `utf8mb4`, foreign keys, and UTC `DATETIME(6)` timestamps.
- Bootstrap 5.3.x and Bootstrap Icons, with minimal framework-free JavaScript.
- PHPUnit 12 and Laravel test utilities.
- Laravel Pint and PHPStan/Larastan for formatting and static analysis.
- Vite only for compiling CSS and JavaScript assets; there is no SPA framework.
- Private filesystem/object storage behind authorized application downloads.
- A queue worker for notification delivery. A database-backed queue is acceptable initially; the domain uses a transactional outbox so the queue transport can later change without altering workflow transactions.

Laravel is used as a modular monolith. Domain behavior is organized by business capability, while the application is built and deployed as one transactional unit. Controllers coordinate HTTP concerns and do not contain business rules or SQL.

## 3. Resolved assumptions

The following defaults remove ambiguity from the source brief. Each is configurable where stated.

1. Privileged MFA is required for administrators, production approvers, production sign-off users, and maker-checker override approvers. Local password authentication is implemented first, with an authentication-provider interface retained for future SSO.
2. A partially successful deployment enters `DEPLOYMENT_DECISION_REQUIRED`. It cannot progress automatically. An independently authorized user must choose controlled production validation or rollback and record a justification.
3. `APPROVED_WITH_CONDITIONS` may progress only when the applicable application policy explicitly permits it. Every condition has an owner, due date, state, and evidence requirement. Closure is blocked while a mandatory condition remains open.
4. Pass-rate thresholds are versioned application policies scoped by release type and environment. Seed defaults are 100% for mandatory tests and 90% overall; administrators may strengthen or lower the overall threshold, but mandatory-test execution cannot be disabled.
5. Governance records, audit logs, sign-offs, test executions, and evidence metadata are retained for seven years by default. The retention value is configurable. The design supports exporting audit/evidence packages to external immutable storage when regulatory WORM retention is required.
6. Human identifiers use `REL-YYYY-NNNNNN`, `HOT-YYYY-NNNNNN`, `FEAT-NNNNNN`, `TC-NNNNNN`, and `DEF-NNNNNN`. Allocation is transactional and identifiers never change.
7. Timestamps are stored in UTC. Dates are displayed in the user's configured timezone. SLA calculations use a configurable organizational business calendar; the seed calendar is Monday-Friday, 08:30-17:00, Indian/Mauritius, excluding configured holidays.
8. Authorization is application-scoped. A role assignment may be global or tied to one application. There is no regional or legal-entity tenancy in version one.
9. CSV is the initial tabular export format. The reporting boundary permits later XLSX generation without changing report queries.
10. Closed releases are read-only. Corrections are recorded as append-only amendments; a closed release is not silently reopened or edited.
11. Reusable test cases belong to an application and optional module, not to a release feature. A release test may link its immutable snapshot to a release feature.
12. Actual production date is derived from the first successful deployment completion timestamp and cached on the release for indexed reporting.

## 4. Architecture

### 4.1 Logical layers

```text
Browser / Bootstrap UI
        |
HTTP Controllers + Form Requests + Middleware
        |
Application Commands / Queries
        |
Domain Services and Policies
  |-- Workflow gates
  |-- Testing rules
  |-- Defect rules
  |-- Approval rules
  |-- Maker-checker rules
  `-- Deployment rules
        |
Repository interfaces
        |
Eloquent/MySQL + private file storage
        |
Transactional audit, activity and outbox records
        |
Asynchronous notification worker
```

### 4.2 Command processing

Every workflow transition, sign-off, deployment result, rollback, override, and closure command follows the same sequence:

1. Authenticate the caller and validate session requirements, including privileged reauthentication where required.
2. Authorize the command using both RBAC and application scope.
3. Validate request shape using a Laravel Form Request and create a typed command DTO.
4. Start a MySQL transaction.
5. Lock the release aggregate row with `SELECT ... FOR UPDATE`.
6. Reject a stale `expected_version` or reused idempotency key with a different request hash.
7. Resolve the workflow and application-policy snapshots attached to the release.
8. Re-evaluate every configured transition gate server-side.
9. Evaluate maker-checker constraints against authoritative actor history.
10. Persist the domain change and increment the aggregate `lock_version`.
11. Append stage history, audit history, public activity, task-projection events, and notification-outbox messages in the same transaction.
12. Commit, then allow workers to deliver notifications.

If any synchronous step fails, the transaction rolls back. Email or queue-delivery failure never reverses a committed workflow action. The outbox worker records the failure and retries according to policy.

### 4.3 Error behavior

- Invalid input returns HTTP 422 with field-specific messages.
- Unauthenticated requests return 401 or redirect to login.
- Unauthorized or out-of-scope requests return 403 without revealing record existence.
- Invalid transitions and business-gate failures return 409 with stable error codes and a list of failed gates.
- Stale optimistic versions return 409 and prompt the user to refresh.
- Duplicate idempotent requests return the original result.
- Unexpected exceptions return a sanitized 500 response containing a correlation ID; details are written only to protected logs.

## 5. Workflow model

### 5.1 Standard workflow

```text
DRAFT
  -> DEVELOPMENT
  -> DEV_TEST_PREPARATION
  -> DEV_TESTING
  -> DEV_SIGNOFF_PENDING
  -> UAT_PREPARATION
  -> UAT_TESTING
  -> UAT_SIGNOFF_PENDING
  -> PRODUCTION_READINESS
  -> PRODUCTION_DEPLOYMENT
  -> PRODUCTION_VALIDATION
  -> PRODUCTION_SIGNOFF_PENDING
  -> RELEASED
  -> CLOSED
```

Rejected Dev sign-off returns to `DEVELOPMENT` or `DEV_TESTING`. Rejected UAT sign-off returns to `DEVELOPMENT`, `UAT_PREPARATION`, or `UAT_TESTING`. A rejected production-readiness review remains in readiness with remediation actions or returns to UAT/development as selected by an authorized approver.

A failed deployment enters `ROLLBACK_PENDING`. A partial deployment enters `DEPLOYMENT_DECISION_REQUIRED`. A production sign-off decision of `ROLLBACK_REQUIRED` also enters `ROLLBACK_PENDING`. A successful rollback enters `ROLLED_BACK`; an authorized release manager may close it as unsuccessful or create a recorded replan transition to Development.

### 5.2 Hotfix workflow

```text
DRAFT
  -> DEVELOPMENT
  -> EMERGENCY_TEST_PREPARATION
  -> EMERGENCY_TESTING
  -> EMERGENCY_APPROVAL
  -> PRODUCTION_READINESS
  -> PRODUCTION_DEPLOYMENT
  -> PRODUCTION_VALIDATION
  -> PRODUCTION_SIGNOFF_PENDING
  -> RETROSPECTIVE_REVIEW
  -> RELEASED
  -> CLOSED
```

Hotfix policy may omit ordinary Dev and UAT stages but cannot omit emergency testing, deployment authorization, production validation, audit, or independent approval. Emergency reason, incident reference, risks, test scope, approval, overrides, and retrospective evidence are mandatory.

### 5.3 Stage versus operational status

`workflow_stage_id` records lifecycle position. `operational_status` records cross-cutting state:

```text
ACTIVE | ON_HOLD | FAILED | ROLLBACK_PENDING |
ROLLED_BACK | CANCELLED | RELEASED | CLOSED
```

Putting a release on hold preserves its underlying workflow stage and blocks normal transitions. `CANCELLED`, `ROLLED_BACK`, and `CLOSED` are terminal except for specifically authorized replan or amendment commands.

### 5.4 Transition gates

`ReleaseWorkflowService` invokes rule handlers through `TransitionRuleRegistry`. Supported handlers are:

- `RequiredFieldsGate`
- `ChecklistCompletionGate`
- `AssignmentGate`
- `MandatoryTestsExecutedGate`
- `PassRateGate`
- `DefectThresholdGate`
- `EvidenceGate`
- `RequiredSignoffGate`
- `MakerCheckerGate`
- `DeploymentResultGate`
- `ConditionsGate`
- `ClosureGate`

Administrators configure which registered handlers apply and their validated parameters. They cannot enter PHP, SQL, template expressions, or arbitrary executable conditions.

Published workflow and policy versions are immutable. A new release receives the current published version; an existing release remains governed by its original snapshot unless a separately audited policy-migration operation is approved.

## 6. Testing rules

Library tests are copied into release/environment-specific snapshots. Editing a library test never changes an active release's test scope. Tests added during execution append to the current scope version and record who added them, when, why, environment, mandatory state, and tester.

Each execution is an immutable attempt. Corrections or retests create another row; they never update an earlier result. Unique `(release_test_case_id, attempt_number)` and command idempotency constraints prevent duplicates.

Calculations use each in-scope test's latest execution:

- Completion percentage = latest `PASS`, `FAIL`, `BLOCKED`, or approved `NOT_APPLICABLE` results divided by all in-scope tests.
- Pass percentage = `PASS / (PASS + FAIL + BLOCKED)`.
- `NOT_TESTED` means no qualifying execution exists.
- `NOT_APPLICABLE` requires a reason. Marking a mandatory test not applicable requires a configured approval.
- All mandatory tests must have a qualifying execution, regardless of overall pass rate.

Thus 42 passed, 3 failed, 2 blocked, and 3 untested out of 50 produces 94% completion and approximately 89% pass rate.

## 7. Maker-checker and sign-off design

Rules are scoped by application, release type, environment, workflow stage, action, and maker role. Specific rules take precedence over general rules, but an applicable independence prohibition cannot be weakened by a less-specific rule.

Supported constraints are:

- `DIFFERENT_USER`
- `NOT_RELEASE_CREATOR`
- `NOT_DEVELOPER_OF_SCOPE`
- `NOT_TEST_EXECUTOR`
- `NOT_DEFECT_RESOLVER`
- `NOT_DEPLOYER`
- `NOT_OVERRIDE_REQUESTER`
- `NOT_PREVIOUS_APPROVER_SLOT`
- `REQUIRES_PERMISSION`
- `MINIMUM_DISTINCT_APPROVERS`

The maker-checker engine derives makers from release creation, assignments, test executions, defect resolutions, and deployment records. It never accepts the browser's statement about who the maker was.

Sign-off requests snapshot approval slots, required roles or permissions, minimum counts, ordering, applicable maker-checker rules, and known makers. A user must possess the required permission and satisfy every applicable independence constraint. Decisions are append-only and are not replaced by later decisions.

An override requires an authorized requester, a specific violated rule, reason, business justification, a different authorized approver, and a single release/stage/action scope. An override does not grant the underlying business permission and does not bypass other gates. Requests, approvals, rejections, expiry, and use are permanently audited.

## 8. RBAC model

Permissions are granular and application-scoped where relevant:

```text
dashboard.view, task.view
release.view, release.create, release.edit, release.assign
release.transition, release.hold, release.resume, release.cancel, release.close
feature.manage
development.update, development.complete
checklist.complete, checklist.configure
test.library.view, test.library.manage
test.scope.manage, test.assign, test.execute, test.complete
defect.create, defect.assign, defect.update, defect.resolve
defect.retest, defect.accept_risk, defect.defer, defect.close
signoff.dev, signoff.uat, signoff.production
production.readiness.review, production.approve
production.deploy, production.rollback, production.validate
maker_checker.override.request, maker_checker.override.approve
attachment.upload, attachment.download
report.view, report.export, audit.view
admin.users, admin.roles, admin.applications
admin.workflow, admin.checklists, admin.maker_checker
admin.notifications, admin.settings
```

Roles are configurable permission bundles. Seed roles are Administrator, Release Manager, Developer, Dev Tester, UAT Tester, Production Tester, Business Approver, Technical Approver, Application Owner, Deployment Engineer, Auditor, and Viewer. Administrator does not automatically receive business sign-off authority. Possessing a sign-off permission only establishes eligibility; maker-checker rules determine independence for each release.

## 9. Relational schema

### 9.1 Conventions

Internal keys are unsigned big integers. Public route identifiers are ULIDs, while user-facing release, feature, test, and defect numbers use transactional sequences. Mutable aggregates contain `lock_version`. All records have UTC timestamps and actor columns as appropriate. Core relationships use foreign keys; JSON is restricted to immutable snapshots, validated rule parameters, and audit diffs.

Normal workflow records are never deleted. Configuration and identity records are deactivated or soft-deleted. Foreign keys use `RESTRICT` for governance history and `CASCADE` only for safe children of unpublished configuration or drafts.

### 9.2 Identity and authorization

- `users`: employee number, name, unique email, password hash, state, timezone, failed-login count, locked-until, last-login, password-changed-at, MFA state, soft-deleted-at.
- `roles`: unique code, name, description, system flag, active flag.
- `permissions`: unique permission code and description.
- `role_permissions`: unique role/permission pair.
- `role_assignments`: user, role, application scope or global scope key, validity dates, assigner; unique user/role/scope.
- `sessions`: session ID, optional user, IP, user agent, payload, last activity.
- `password_reset_tokens`: email, hashed token, expiry.
- `login_events`: user/email, result, IP, user agent, timestamp, correlation ID.
- `security_events`: user, event code, metadata, IP, timestamp, correlation ID.

### 9.3 Configurable governance

- `applications`: unique code/name, description, criticality, active flag.
- `application_modules`: application, unique code within application, name, active flag.
- `application_owners`: application, user, owner type, validity dates.
- `release_types`: unique code, name, active flag, hotfix flag.
- `priority_definitions`: unique code, label, rank, Bootstrap color token, active flag.
- `defect_severities`: unique code, label, rank, default blocking behavior, SLA.
- `defect_priorities`: unique code, label, rank, SLA.
- `system_settings`: unique typed key, encrypted value where applicable, revision, modifier.
- `business_calendars`: name, timezone, working days and hours, active flag.
- `business_calendar_holidays`: calendar, date, name; unique calendar/date.
- `sla_policies`: application/release-type/environment scope, event code, duration, calendar, effective dates.
- `workflow_definitions`: unique code/version, workflow type, active dates, publication state.
- `workflow_stages`: workflow, unique stage code, name, display order, terminal flag.
- `workflow_transitions`: workflow, source stage, target stage, unique action code, permission, comment requirement.
- `workflow_transition_rules`: transition, registered rule code, validated configuration JSON, order, enabled flag.
- `application_policies`: application, release type, workflow version, pass thresholds, evidence and defect parameters, effective dates, version.
- `policy_approval_requirements`: policy, gate, slot code, required permission/role, minimum count, sequence.

### 9.4 Releases and development

- `number_sequences`: identifier type, year, next value; unique type/year and locked during allocation.
- `releases`: public ULID and release number, primary application, workflow/policy version, stage, operational status, release type, priority, version, title, descriptions, owners, manager, target dates, actual production date, implementation/technical/deployment/database/configuration notes, rollback plan, release notes, hotfix details, lock version.
- `release_impacted_applications`: unique release/application pair.
- `release_impacted_modules`: unique release/module pair.
- `release_dependencies`: release, dependency type, optional dependent release, external reference, description.
- `release_features`: public feature number, release, optional module, type, priority, title, descriptions, business reference, status, lock version.
- `development_records`: unique feature, status, start/target/actual dates, branch, commit, merge request, unit-test result, notes and documentation references.
- `release_assignments`: release, optional feature, environment, assignment type, user, deadline, state, assigner.
- `release_stage_history`: release, from/to stage, action, actor, timestamp, correlation ID, comments; append-only.
- `transition_commands`: release, actor, idempotency key, action, request hash, result, resulting stage/version; unique actor/idempotency key.

### 9.5 Checklists

- `checklist_templates`: unique code/version, application/release-type/stage/environment scope, name, effective dates, publication state.
- `checklist_template_items`: template, stable item code, label, mandatory flag, evidence requirement, display order.
- `release_checklists`: release, source template/version, stage, environment, status, generated-at.
- `release_checklist_items`: release checklist and immutable snapshot of item code, label, mandatory/evidence rules, order.
- `release_checklist_results`: unique release checklist item, completion state, actor, timestamp, comment.

### 9.6 Testing

- `test_cases`: public test number, application, optional module, title, description, preconditions, expected result, type, priority, mandatory default, creator, active flag.
- `test_case_steps`: test case, sequence, action, expected step result; unique test/sequence.
- `release_test_cases`: release, optional feature, environment, origin, optional source test, mandatory flag, addition reason, scope version, creator, immutable field snapshot.
- `release_test_steps`: release test, sequence, action, expected result; unique release test/sequence.
- `test_assignments`: release test, tester, deadline, assigner, state, assigned-at.
- `test_executions`: release test, optional assignment, attempt number, tester, result, actual result, comments, timestamp, retest-required, idempotency key; unique release test/attempt and tester/idempotency key.
- `defect_retests`: defect, source execution, retest execution; unique retest execution.

### 9.7 Defects

- `defects`: public defect number, release, optional feature/test/origin execution, environment, summary, description, severity, priority, assignee, state, root cause, resolution, creator, relevant dates, lock version.
- `defect_history`: defect, old/new state and values, actor, reason, timestamp; append-only.
- `defect_comments`: defect, author, comment, timestamp; append-only.
- `defect_acceptances`: defect, risk/defer decision, justification, expiry or target release, approver, approval reference.

### 9.8 Sign-offs and maker-checker

- `signoff_requests`: release, gate, environment, source stage-history record, state, requester, requested-at.
- `signoff_requirements`: request, slot code, snapshotted permission/role, minimum count, independence rules, sequence.
- `signoffs`: request, requirement slot, approver, decision, comments, conditions, timestamp; append-only with a unique decision key.
- `approval_conditions`: signoff, condition, owner, due date, state, evidence requirement.
- `maker_checker_rules`: application/release-type/environment/stage/action scope, maker role, checker permission/role, constraint code, priority, effective dates, version.
- `maker_checker_overrides`: release, stage/action, violated rule, requester, reason, justification, state, expiry.
- `maker_checker_override_approvals`: override, independent approver, decision, comments, timestamp.

### 9.9 Production and closure

- `deployments`: release, attempt number, owner, authorizing signoff, version, planned/actual times, result, scripts/config/database changes, comments, idempotency key; unique release/attempt.
- `deployment_steps`: deployment, sequence, instruction, result, executor, timestamp.
- `rollbacks`: release, deployment, attempt number, reason, initiator, approver, times, result, incident reference, comments.
- `rollback_steps`: rollback, sequence, instruction, result, executor, timestamp.
- `post_release_observations`: release, category, description, owner, state, recorder, timestamp.

Production validation reuses release tests and executions with the `PRODUCTION` environment.

### 9.10 Evidence, communication, and audit

- `attachments`: public ULID, original name, opaque storage key, extension, detected MIME, size, SHA-256, encryption metadata, scan state, uploader, timestamp.
- Typed attachment links: `release_attachments`, `feature_attachments`, `development_attachments`, `test_execution_attachments`, `defect_attachments`, `signoff_attachments`, `deployment_attachments`, `rollback_attachments`, and `observation_attachments`.
- `notification_templates`: event code, channel, subject/body, application scope, version, enabled flag.
- `notification_outbox`: unique event ID, release, type, payload snapshot, state, attempts, next-attempt time.
- `notifications`: recipient, event, title/body, read-at.
- `email_logs`: outbox record, recipient, subject, status, provider reference, attempts, sent-at, sanitized error.
- `audit_logs`: actor, action, IP, correlation ID, optional release/feature/environment, entity type/ID, previous/new JSON, comment, timestamp, previous hash, row hash; append-only.
- `activity_logs`: release, public event type/message, actor, timestamp; append-only.
- `user_tasks`: rebuildable dashboard projection containing assignee, action, due date, source reference, priority, and state.
- `report_exports`: report type, filter snapshot, requester, state, protected output attachment, expiry.

Audit-table update and delete privileges are denied to the application account, and database triggers reject mutation. Hash chaining provides tamper evidence. External immutable backups remain necessary to defend against database-administrator compromise.

## 10. Module and folder structure

```text
app/
  Domain/
    Identity/
    ApplicationGovernance/
    Release/
    Workflow/
    Checklist/
    Testing/
    Defect/
    Approval/
    Deployment/
    Notification/
    Audit/
    Shared/
  Application/
    Commands/
    Queries/
    DTOs/
  Infrastructure/
    Persistence/Eloquent/
    Persistence/Repositories/
    Mail/
    Files/
    Queue/
    Audit/
  Http/
    Controllers/Admin/
    Controllers/Release/
    Controllers/Testing/
    Controllers/Production/
    Controllers/Reporting/
    Requests/
    Middleware/
    ViewModels/
  Policies/
  Providers/
  Console/Commands/
config/
database/{migrations,factories,seeders}/
resources/
  views/{layouts,components,dashboard,releases,testing,defects,production,reports,admin}/
  css/
  js/
routes/{web.php,auth.php,admin.php}
storage/{app/private,logs}/
tests/{Unit,Feature,Integration,Browser}/
```

## 11. Major services

- `ReleaseWorkflowService`: lists and executes valid transitions.
- `TransitionRuleRegistry`: resolves safe gate handlers.
- `ReleasePolicyResolver`: selects and snapshots effective governance.
- `ReleaseService`: manages releases, features, assignments, hold, and resume.
- `DevelopmentCompletionService`: enforces development completion.
- `ChecklistService`: materializes templates and records results.
- `TestScopeService`: snapshots, copies, and appends tests.
- `TestAssignmentService`: assigns testers and creates tasks.
- `TestExecutionService`: appends attempts and calculates progress.
- `DefectService` and `DefectRetestService`: manage defect lifecycle and execution links.
- `SignoffService`: requests and records approvals.
- `MakerCheckerPolicyEngine`: resolves rules, makers, and eligible checkers.
- `OverrideService`: manages independently approved exceptions.
- `ProductionReadinessService`: evaluates the production gate.
- `DeploymentService` and `RollbackService`: manage production attempts.
- `ReleaseClosureService`: validates and freezes completed releases.
- `AttachmentService`: validates, quarantines, hashes, scans, and serves files.
- `AuditRecorder` and `ActivityRecorder`: append protected histories.
- `OutboxPublisher` and `NotificationDispatcher`: commit and deliver messages safely.

Repositories are introduced for domain aggregates and specialized reporting queries, not mechanically for every Eloquent model.

## 12. Route and controller design

Resource and command routes are grouped as follows:

```text
/auth/*
/dashboard
/tasks
/releases
/releases/{release}
/releases/{release}/features
/releases/{release}/assignments
/releases/{release}/transitions
/releases/{release}/hold
/releases/{release}/resume
/releases/{release}/development
/releases/{release}/checklists/{checklist}
/releases/{release}/testing/{environment}
/release-tests/{releaseTest}/assignments
/release-tests/{releaseTest}/executions
/releases/{release}/defects
/defects/{defect}/transitions
/defects/{defect}/retests
/releases/{release}/signoffs/{gate}
/signoff-requests/{request}/decisions
/maker-checker-overrides
/maker-checker-overrides/{override}/decision
/releases/{release}/production-readiness
/releases/{release}/deployments
/deployments/{deployment}/result
/deployments/{deployment}/rollback
/releases/{release}/production-validation
/releases/{release}/closure
/attachments/{attachment}
/reports/*
/calendar
/admin/users
/admin/roles
/admin/applications
/admin/release-types
/admin/workflows
/admin/checklists
/admin/maker-checker
/admin/email-templates
/admin/settings
```

There is no generic endpoint that accepts a status value. State-changing routes express domain commands and require CSRF tokens, policies, application scope, an expected aggregate version, and an idempotency key.

## 13. Presentation and notification design

The authenticated shell uses a responsive top navbar, collapsible left navigation, breadcrumbs, global search, notification indicator, user menu, and accessible Bootstrap alerts/toasts. Desktop and laptop layouts are primary; tables gain horizontal scrolling or condensed cards on tablets. Animation is limited to Bootstrap's standard interaction feedback.

The dashboard contains:

- Release-stage cards covering Draft, Development, Dev Testing, Dev Sign-off, UAT, UAT Sign-off, Production Readiness, Deployment, Validation, Production Sign-off, Released, On Hold, Failed, and Rolled Back.
- A My Tasks table sourced from the rebuildable task projection, including development, testing, retesting, approval, production-validation, and overdue actions.
- Testing totals and progress bars showing pass, fail, blocked, untested, completion, and pass percentages.
- Defect totals by severity, state, retest readiness, and overdue state.
- Upcoming, recent, overdue, and approval-waiting release tables.

The release detail page has a persistent workflow stepper and tabs for Overview, Features, Development, Dev Testing, Dev Sign-off, UAT, UAT Sign-off, Production Readiness, Deployment, Production Validation, Production Sign-off, Defects, Attachments, Activity, and Audit Trail. Buttons reflect server-provided capabilities, but every submitted command is independently authorized and revalidated.

Tables use server-side filtering, deterministic sorting, and pagination. Global and contextual release search covers release number, application, version, feature, status, type, developer, tester, manager, approver, dates, and environment. Calendar entries use target Dev, UAT, production, hotfix, and completion dates with application/type/owner/status filters.

Reports cover Release History, Release Status, Testing Summary, Test Execution, Failed Tests, Defects, Defect Aging, Sign-offs, Production Releases, Rollbacks, Maker-Checker Overrides, Application Release History, User Workload, Tester Workload, and Release SLA. Exports contain a filter snapshot, requester, creation time, and expiry and are downloaded through authorization rather than a public URL.

Notification event codes cover development assignment, testing assignment, deadline approaching, testing overdue, test failure, critical defect, developer assignment, ready for retest, testing completed, sign-off requested, sign-off approved, sign-off rejected, UAT assignment, production approval, deployment, production-validation assignment, production-validation failure, rollback, and release completion. Template variables are allowlisted and escaped. Each recipient produces an independently traceable delivery record. Scheduler commands create reminder/escalation outbox events idempotently.

## 14. Index and constraint strategy

In addition to primary and foreign-key indexes, migrations create:

- Unique release, feature, test-case, and defect human identifiers.
- Unique workflow code/version, policy scope/version, checklist code/version, and template code/version.
- Release indexes on application/stage/status, type/status, manager/status, target Dev date, target UAT date, target production date, and created-at.
- Assignment indexes on user/state/deadline and release/environment/type.
- Release-test indexes on release/environment/feature and environment/mandatory.
- Test-execution indexes on release-test/timestamp, tester/timestamp, and result/timestamp.
- Defect indexes on release/environment/status, assignee/status, severity/status, priority/status, and created-at.
- Sign-off indexes on release/gate/state and pending requirement/eligible permission.
- Deployment indexes on release/attempt and result/completed-at.
- Notification indexes on outbox state/next-attempt and recipient/read-at.
- Audit and activity indexes on release/timestamp, entity type/entity ID/timestamp, actor/timestamp, action/timestamp, and correlation ID.
- Unique idempotency constraints for transition, execution, sign-off, deployment, rollback, override, and scheduled-notification commands.

Frequently used dashboard queries are implemented through dedicated query objects. `user_tasks` is a non-authoritative read model that can be rebuilt from assignments, defects, approvals, conditions, and validation work; a projection failure cannot authorize or complete business activity.

## 15. Migration order

1. Authentication, sessions, login and security events.
2. Roles, permissions, and scoped role assignments.
3. Applications, modules, release types, priorities, calendars, and SLA configuration.
4. Workflow definitions, stages, transitions, rules, and application policies.
5. Releases, features, development, assignments, dependencies, and stage history.
6. Checklist templates, release snapshots, and results.
7. Test library, release tests, assignments, and immutable executions.
8. Defects, histories, comments, acceptances, and retest links.
9. Sign-off requests, requirements, decisions, and conditions.
10. Maker-checker rules, overrides, and override approvals.
11. Deployments, steps, rollbacks, and observations.
12. Attachments and typed evidence links.
13. Notification templates, outbox, notifications, and email logs.
14. Audit/activity history and read-model projections.
15. Search, dashboard, SLA, and concurrency indexes.
16. Canonical permission, role, workflow, checklist, test-type, and defect-classification seeders.

Migration tests create an empty schema, run all migrations and seeders, verify constraints, roll back where safe, and rebuild it.

## 16. Security design

- Argon2id password hashing and rehash-on-login.
- MFA for privileged roles and privileged-operation reauthentication.
- Session regeneration after authentication and privilege changes.
- Configurable inactivity and absolute session limits.
- Secure, HttpOnly, SameSite cookies with the Secure flag under HTTPS.
- CSRF protection on every browser mutation.
- Blade escaping by default and sanitization of permitted rich text.
- Parameterized Eloquent/query-builder access; no interpolated SQL.
- Form Request validation, typed commands, and explicit mass-assignment allowlists.
- Policy enforcement at route and use-case boundaries.
- Application-scoped record resolution to prevent insecure direct object access.
- Throttling of login, password reset, exports, and attachment downloads.
- Lockout events and authorized administrative unlock.
- Content Security Policy, HSTS, `frame-ancestors`, nosniff, referrer, and permissions-policy headers.
- TLS for browser, SMTP, MySQL, and storage connections.
- Separate runtime, migration, reporting, and backup database privileges.
- Storage outside the public web root with authorized streaming downloads.
- Extension, MIME, magic-byte, size, image-decoding, and malware checks.
- Opaque file keys, SHA-256 checksums, quarantine, and encryption at rest.
- Environment or secret-manager configuration; secrets never enter source control.
- Central sanitized exception handling and correlation IDs.
- Structured log redaction and protected log access.
- Append-only audit controls, hash chaining, backups, and retention monitoring.
- Dependency vulnerability scanning, lock-file review, and production debug-mode enforcement.

## 17. Testing strategy

Unit tests cover domain rules without HTTP or persistence. Feature tests cover authentication, authorization, validation, application scope, CSRF, and commands. Integration tests use MySQL 8.4 to exercise transactions, foreign keys, uniqueness, locking, and the outbox. Browser smoke tests cover the essential Bootstrap workflows.

Required suites include:

- Authentication, lockout, MFA, session rotation, and expiry.
- Every role and permission boundary, including application-scope isolation.
- Release creation and every allowed and forbidden transition.
- Mandatory checklist, tester assignment, evidence, pass-rate, and defect gates.
- Immutable test execution and multi-attempt retesting.
- Dev, UAT, production-readiness, and production sign-off.
- Maker-checker rejection, multi-approver requirements, and controlled overrides.
- Deployment success, partial success, failure, rollback, validation, and closure.
- Duplicate approvals, double-clicks, stale versions, and concurrent transitions.
- Notification failure, retry, and non-duplication after successful delivery.
- Audit immutability and hash-chain verification.
- File traversal, MIME spoofing, executables, oversized uploads, malware quarantine, and unauthorized download.
- Closed-release mutation attempts and append-only amendments.
- Dashboard calculations, search filters, pagination, SLA, and export authorization.

Static analysis, formatting, migration verification, unit/feature/integration tests, and dependency-audit checks run in CI. Security-sensitive negative tests are required; a success-path test alone is insufficient.

## 18. Incremental delivery plan

Each implementation phase includes migrations, domain behavior, authorization, Bootstrap UI, validation, automated tests, executed verification, and a security review.

1. **Foundation:** Laravel bootstrap, environment validation, MySQL, layout, exception handling, logging, CI, and quality tools.
2. **Identity and RBAC:** authentication, MFA, sessions, lockout, users, roles, permissions, and application-scoped assignments.
3. **Application configuration:** applications, modules, release types, priorities, calendars, SLA, and settings.
4. **Versioned governance:** workflows, transitions, gate configuration, policies, and checklists.
5. **Audit, evidence, and outbox:** immutable audit/activity, protected attachments, and transactional notification events.
6. **Maker-checker and approvals:** rule engine, approval slots, sign-off requests, conditions, and overrides.
7. **Release core:** releases, features, assignments, detail screen, stepper, history, and transition orchestration.
8. **Development:** development records, completion gates, correction loop, documentation, and evidence.
9. **Testing framework:** test library, snapshots, assignment, execution, progress, and additional tests.
10. **Defects and retesting:** defects, history, resolution, risk acceptance, and immutable retests.
11. **Dev and UAT governance:** preparation, environment-separated testing, notifications, and sign-offs.
12. **Production lifecycle:** readiness, deployment, partial/failure decisions, rollback, validation, sign-off, closure, and hotfixes.
13. **Notifications and scheduling:** templates, SMTP, retry, reminders, overdue processing, and escalation.
14. **Dashboard and reporting:** summary cards, tasks, search, calendar, CSV exports, SLA, and workload reports.
15. **Hardening and readiness:** permission audit, concurrency and security testing, index review, performance tests, backup/restore exercise, and production runbooks.

The detailed implementation plan will decompose these phases into independently reviewable, test-driven tasks after this design is approved.
