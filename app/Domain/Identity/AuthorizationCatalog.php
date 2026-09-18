<?php

declare(strict_types=1);

namespace App\Domain\Identity;

use App\Domain\Identity\Enums\PermissionScope;

final class AuthorizationCatalog
{
    /** @var array<string, PermissionScope> */
    private const array PERMISSIONS = [
        'admin.users' => PermissionScope::Global,
        'admin.roles' => PermissionScope::Global,
        'admin.applications' => PermissionScope::Global,
        'admin.workflow' => PermissionScope::Global,
        'admin.checklists' => PermissionScope::Global,
        'admin.maker_checker' => PermissionScope::Global,
        'admin.notifications' => PermissionScope::Global,
        'admin.settings' => PermissionScope::Global,
        'dashboard.view' => PermissionScope::Application,
        'task.view' => PermissionScope::Application,
        'release.view' => PermissionScope::Application,
        'release.create' => PermissionScope::Application,
        'release.edit' => PermissionScope::Application,
        'release.assign' => PermissionScope::Application,
        'release.transition' => PermissionScope::Application,
        'release.hold' => PermissionScope::Application,
        'release.resume' => PermissionScope::Application,
        'release.cancel' => PermissionScope::Application,
        'release.close' => PermissionScope::Application,
        'feature.manage' => PermissionScope::Application,
        'development.update' => PermissionScope::Application,
        'development.complete' => PermissionScope::Application,
        'checklist.complete' => PermissionScope::Application,
        'checklist.configure' => PermissionScope::Application,
        'test.library.view' => PermissionScope::Application,
        'test.library.manage' => PermissionScope::Application,
        'test.scope.manage' => PermissionScope::Application,
        'test.assign' => PermissionScope::Application,
        'test.execute' => PermissionScope::Application,
        'test.complete' => PermissionScope::Application,
        'defect.create' => PermissionScope::Application,
        'defect.assign' => PermissionScope::Application,
        'defect.update' => PermissionScope::Application,
        'defect.resolve' => PermissionScope::Application,
        'defect.retest' => PermissionScope::Application,
        'defect.accept_risk' => PermissionScope::Application,
        'defect.defer' => PermissionScope::Application,
        'defect.close' => PermissionScope::Application,
        'signoff.dev' => PermissionScope::Application,
        'signoff.uat' => PermissionScope::Application,
        'signoff.production' => PermissionScope::Application,
        'production.readiness.review' => PermissionScope::Application,
        'production.approve' => PermissionScope::Application,
        'production.deploy' => PermissionScope::Application,
        'production.rollback' => PermissionScope::Application,
        'production.validate' => PermissionScope::Application,
        'maker_checker.override.request' => PermissionScope::Application,
        'maker_checker.override.approve' => PermissionScope::Application,
        'attachment.upload' => PermissionScope::Application,
        'attachment.download' => PermissionScope::Application,
        'report.view' => PermissionScope::Application,
        'report.export' => PermissionScope::Application,
        'audit.view' => PermissionScope::Application,
    ];

    /** @var array<string, list<string>> */
    private const array ROLE_PERMISSIONS = [
        'Administrator' => [
            'dashboard.view', 'task.view', 'report.view', 'report.export', 'audit.view',
            'admin.users', 'admin.roles', 'admin.applications', 'admin.workflow',
            'admin.checklists', 'admin.maker_checker', 'admin.notifications', 'admin.settings',
        ],
        'Release Manager' => [
            'dashboard.view', 'task.view', 'release.view', 'release.create', 'release.edit',
            'release.assign', 'release.transition', 'release.hold', 'release.resume',
            'release.cancel', 'release.close', 'feature.manage', 'development.update',
            'checklist.complete', 'test.library.view', 'test.scope.manage', 'test.assign',
            'test.complete', 'defect.create', 'defect.assign', 'defect.update', 'defect.close',
            'maker_checker.override.request', 'attachment.upload', 'attachment.download',
            'report.view', 'report.export',
        ],
        'Developer' => [
            'dashboard.view', 'task.view', 'release.view', 'feature.manage',
            'development.update', 'development.complete', 'checklist.complete',
            'test.library.view', 'defect.create', 'defect.update', 'defect.resolve',
            'attachment.upload', 'attachment.download',
        ],
        'Dev Tester' => [
            'dashboard.view', 'task.view', 'release.view', 'test.library.view', 'test.execute',
            'defect.create', 'defect.update', 'defect.retest', 'attachment.upload', 'attachment.download',
        ],
        'UAT Tester' => [
            'dashboard.view', 'task.view', 'release.view', 'test.library.view', 'test.execute',
            'defect.create', 'defect.update', 'defect.retest', 'attachment.upload', 'attachment.download',
        ],
        'Production Tester' => [
            'dashboard.view', 'task.view', 'release.view', 'test.execute', 'defect.create',
            'defect.update', 'defect.retest', 'production.validate', 'attachment.upload', 'attachment.download',
        ],
        'Business Approver' => [
            'dashboard.view', 'task.view', 'release.view', 'signoff.uat', 'signoff.production',
            'attachment.upload', 'attachment.download',
        ],
        'Technical Approver' => [
            'dashboard.view', 'task.view', 'release.view', 'signoff.dev',
            'production.readiness.review', 'production.approve', 'signoff.production',
            'attachment.upload', 'attachment.download',
        ],
        'Application Owner' => [
            'dashboard.view', 'task.view', 'release.view', 'release.create', 'release.edit',
            'release.assign', 'feature.manage', 'production.readiness.review', 'attachment.upload',
            'attachment.download', 'report.view', 'report.export',
        ],
        'Deployment Engineer' => [
            'dashboard.view', 'task.view', 'release.view', 'production.deploy',
            'production.rollback', 'attachment.upload', 'attachment.download',
        ],
        'Auditor' => [
            'dashboard.view', 'release.view', 'report.view', 'report.export', 'audit.view',
            'attachment.download',
        ],
        'Viewer' => ['dashboard.view', 'release.view', 'report.view'],
    ];

    /** @var array<string, string> */
    private const array ROLE_CODES = [
        'Administrator' => 'administrator',
        'Release Manager' => 'release_manager',
        'Developer' => 'developer',
        'Dev Tester' => 'dev_tester',
        'UAT Tester' => 'uat_tester',
        'Production Tester' => 'production_tester',
        'Business Approver' => 'business_approver',
        'Technical Approver' => 'technical_approver',
        'Application Owner' => 'application_owner',
        'Deployment Engineer' => 'deployment_engineer',
        'Auditor' => 'auditor',
        'Viewer' => 'viewer',
    ];

    /** @return array<string, PermissionScope> */
    public static function permissions(): array
    {
        return self::PERMISSIONS;
    }

    /** @return array<string, list<string>> */
    public static function rolePermissions(): array
    {
        $roles = self::ROLE_PERMISSIONS;

        foreach ($roles as &$permissions) {
            sort($permissions);
        }

        return $roles;
    }

    /** @return array<string, string> */
    public static function roleCodes(): array
    {
        return self::ROLE_CODES;
    }
}
