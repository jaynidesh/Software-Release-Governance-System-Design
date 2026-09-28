<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Domain\Identity\Enums\UserState;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Notifications\Identity\ActivationInvitationNotification;
use App\Services\Identity\IdentityEventRecorder;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;

final class BootstrapAdministratorCommand extends Command
{
    protected $signature = 'identity:bootstrap-admin';

    protected $description = 'Interactively create the first invited administrator principal';

    public function __construct(private readonly IdentityEventRecorder $events)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        if (! $this->input->isInteractive()) {
            $this->error('Administrator bootstrap is interactive only.');

            return self::FAILURE;
        }

        $attributes = [
            'employee_number' => $this->ask('Employee number (optional)'),
            'name' => $this->ask('Name'),
            'email' => $this->ask('Email'),
            'timezone' => $this->ask('Timezone'),
        ];
        $attributes['employee_number'] = trim((string) $attributes['employee_number']) ?: null;
        $attributes['name'] = trim((string) $attributes['name']);
        $attributes['email'] = mb_strtolower(trim((string) $attributes['email']));
        $attributes['timezone'] = trim((string) $attributes['timezone']);
        $validator = Validator::make($attributes, [
            'employee_number' => ['nullable', 'string', 'max:100', 'unique:users,employee_number'],
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email:rfc', 'max:255', 'unique:users,email'],
            'timezone' => ['required', 'timezone'],
        ]);

        if ($validator->fails()) {
            foreach ($validator->errors()->all() as $error) {
                $this->error($error);
            }

            return self::FAILURE;
        }

        $created = DB::transaction(function () use ($attributes): ?User {
            $administrator = Role::query()
                ->where('code', 'administrator')
                ->lockForUpdate()
                ->firstOrFail();
            $exists = RoleAssignment::query()
                ->where('role_id', $administrator->id)
                ->whereNull('application_id')
                ->whereNull('revoked_at')
                ->where('starts_at', '<=', now())
                ->where(static function ($query): void {
                    $query->whereNull('ends_at')->orWhere('ends_at', '>', now());
                })
                ->whereHas('user', static function ($query): void {
                    $query->where('state', '!=', UserState::Deactivated);
                })
                ->lockForUpdate()
                ->exists();

            if ($exists) {
                return null;
            }

            $user = User::query()->create([
                ...$attributes,
                'state' => UserState::Invited,
                'email_verified_at' => null,
                'invited_at' => now(),
                'invitation_expires_at' => now()->addDays((int) config('identity.invitation_ttl_days')),
                'activated_at' => null,
            ]);
            RoleAssignment::query()->create([
                'user_id' => $user->id,
                'role_id' => $administrator->id,
                'application_id' => null,
                'starts_at' => now(),
                'ends_at' => null,
                'assigned_by' => null,
            ]);
            $this->events->security(
                'identity.administrator.bootstrapped',
                null,
                $user,
                [],
                null,
                'artisan',
                null,
            );
            DB::afterCommit(static fn () => $user->notify(new ActivationInvitationNotification));

            return $user;
        }, 3);

        if (! $created instanceof User) {
            $this->error('An administrator principal already exists.');

            return self::FAILURE;
        }

        $this->info('The first administrator was invited.');

        return self::SUCCESS;
    }
}
