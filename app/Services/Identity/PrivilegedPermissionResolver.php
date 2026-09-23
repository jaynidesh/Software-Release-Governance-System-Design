<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Models\Permission;
use App\Models\User;

final class PrivilegedPermissionResolver
{
    /** @var list<string> */
    private const BASELINE = [
        'admin.',
        'production.approve',
        'signoff.production',
        'maker_checker.override.approve',
    ];

    public function isPrivileged(string $permissionCode): bool
    {
        foreach ($this->rules() as $rule) {
            if ($permissionCode === $rule
                || (str_ends_with($rule, '.') && str_starts_with($permissionCode, $rule))) {
                return true;
            }
        }

        return false;
    }

    public function userIsPrivileged(User $user): bool
    {
        return Permission::query()
            ->select('permissions.code')
            ->join('role_permissions', 'role_permissions.permission_id', '=', 'permissions.id')
            ->join('roles', 'roles.id', '=', 'role_permissions.role_id')
            ->join('role_assignments', 'role_assignments.role_id', '=', 'roles.id')
            ->leftJoin('applications', 'applications.id', '=', 'role_assignments.application_id')
            ->where('role_assignments.user_id', $user->getKey())
            ->where('roles.is_active', true)
            ->whereNull('roles.deleted_at')
            ->where('role_assignments.starts_at', '<=', now())
            ->whereNull('role_assignments.revoked_at')
            ->where(static function ($query): void {
                $query->whereNull('role_assignments.ends_at')
                    ->orWhere('role_assignments.ends_at', '>', now());
            })
            ->where(static function ($query): void {
                $query->whereNull('role_assignments.application_id')
                    ->orWhere('applications.is_active', true);
            })
            ->pluck('permissions.code')
            ->contains(fn (mixed $code): bool => is_string($code) && $this->isPrivileged($code));
    }

    /** @return list<string> */
    private function rules(): array
    {
        $configured = array_filter(
            (array) config('identity.additional_privileged_permissions', []),
            static fn (mixed $rule): bool => is_string($rule) && $rule !== '',
        );

        // Accept the full configured list for compatibility, while always restoring the immutable baseline.
        $legacyConfigured = array_filter(
            (array) config('identity.privileged_permissions', []),
            static fn (mixed $rule): bool => is_string($rule) && $rule !== '',
        );

        return array_values(array_unique([...self::BASELINE, ...$configured, ...$legacyConfigured]));
    }
}
