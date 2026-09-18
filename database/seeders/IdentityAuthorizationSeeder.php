<?php

declare(strict_types=1);

namespace Database\Seeders;

use App\Domain\Identity\AuthorizationCatalog;
use App\Models\Permission;
use App\Models\Role;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class IdentityAuthorizationSeeder extends Seeder
{
    public function run(): void
    {
        DB::transaction(function (): void {
            foreach (AuthorizationCatalog::permissions() as $code => $scope) {
                Permission::query()->updateOrCreate(
                    ['code' => $code],
                    [
                        'description' => Str::headline(str_replace('.', ' ', $code)).'.',
                        'scope_type' => $scope,
                    ],
                );
            }

            $roleCodes = AuthorizationCatalog::roleCodes();

            foreach (AuthorizationCatalog::rolePermissions() as $name => $permissionCodes) {
                $role = Role::query()->updateOrCreate(
                    ['code' => $roleCodes[$name]],
                    [
                        'name' => $name,
                        'description' => sprintf('System role for %s responsibilities.', $name),
                        'is_system' => true,
                        'is_active' => true,
                    ],
                );

                $permissionIds = Permission::query()
                    ->whereIn('code', $permissionCodes)
                    ->pluck('id')
                    ->all();

                $role->permissions()->sync($permissionIds);
            }
        });
    }
}
