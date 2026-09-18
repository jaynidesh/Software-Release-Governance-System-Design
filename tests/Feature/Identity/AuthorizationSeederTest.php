<?php

declare(strict_types=1);

namespace Tests\Feature\Identity;

use App\Domain\Identity\AuthorizationCatalog;
use App\Domain\Identity\Enums\PermissionScope;
use App\Models\Permission;
use App\Models\Role;
use App\Models\User;
use Database\Seeders\DatabaseSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use LogicException;
use Tests\TestCase;

final class AuthorizationSeederTest extends TestCase
{
    use RefreshDatabase;

    public function test_catalog_classifies_every_canonical_permission_and_nothing_else(): void
    {
        self::assertSame($this->permissionScopes(), AuthorizationCatalog::permissions());
    }

    public function test_catalog_defines_every_exact_initial_system_role_bundle(): void
    {
        self::assertSame($this->rolePermissions(), AuthorizationCatalog::rolePermissions());

        $administrator = AuthorizationCatalog::rolePermissions()['Administrator'];
        self::assertNotContains('signoff.dev', $administrator);
        self::assertNotContains('signoff.uat', $administrator);
        self::assertNotContains('signoff.production', $administrator);
        self::assertNotContains('production.approve', $administrator);
        self::assertNotContains('production.deploy', $administrator);
        self::assertNotContains('maker_checker.override.approve', $administrator);
    }

    public function test_database_seeder_is_idempotent_and_creates_no_default_user(): void
    {
        $this->seed(DatabaseSeeder::class);
        $this->seed(DatabaseSeeder::class);

        self::assertSame(0, User::query()->count());
        self::assertSame(count($this->permissionScopes()), Permission::query()->count());
        self::assertSame(count($this->rolePermissions()), Role::query()->count());

        $seededScopes = Permission::query()->orderBy('code')->get()
            ->mapWithKeys(static fn (Permission $permission): array => [$permission->code => $permission->scope_type])
            ->all();
        $expectedScopes = $this->permissionScopes();
        ksort($expectedScopes);
        self::assertSame($expectedScopes, $seededScopes);

        foreach ($this->rolePermissions() as $roleName => $expectedPermissions) {
            $role = Role::query()->where('name', $roleName)->firstOrFail();
            self::assertTrue($role->is_system);
            self::assertTrue($role->is_active);
            self::assertSame(
                $expectedPermissions,
                $role->permissions()->orderBy('code')->pluck('code')->sort()->values()->all(),
            );
        }
    }

    public function test_seeded_system_roles_cannot_be_deleted(): void
    {
        $this->seed(DatabaseSeeder::class);
        $administrator = Role::query()->where('code', 'administrator')->firstOrFail();

        try {
            $administrator->delete();
            self::fail('System roles must reject deletion.');
        } catch (LogicException) {
            self::assertFalse($administrator->fresh()->trashed());
        }
    }

    /** @return array<string, PermissionScope> */
    private function permissionScopes(): array
    {
        return [
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
    }

    /** @return array<string, list<string>> */
    private function rolePermissions(): array
    {
        $roles = [
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

        foreach ($roles as &$permissions) {
            sort($permissions);
        }

        return $roles;
    }
}
