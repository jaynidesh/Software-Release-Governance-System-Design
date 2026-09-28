<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Domain\Identity\Enums\UserState;
use App\Models\AuthChallenge;
use App\Models\AuthSession;
use App\Models\PendingAuthentication;
use App\Models\Role;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Notifications\Identity\AdministratorRecoveryNotification;
use App\Services\Identity\IdentityEventRecorder;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;

final class RecoverAdministratorCommand extends Command
{
    protected $signature = 'identity:recover-admin';

    protected $description = 'Interactively recover an existing administrator principal';

    public function __construct(private readonly IdentityEventRecorder $events)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        if (! $this->input->isInteractive()) {
            $this->error('Administrator recovery is interactive only.');

            return self::FAILURE;
        }

        $email = mb_strtolower(trim((string) $this->ask('Administrator email')));
        $incidentReference = trim((string) $this->ask('Incident reference'));
        $reason = trim((string) $this->ask('Recovery reason'));
        $confirmation = (string) $this->ask(sprintf('Type exactly "RECOVER %s" to continue', $email));
        $validator = Validator::make([
            'email' => $email,
            'incident_reference' => $incidentReference,
            'reason' => $reason,
        ], [
            'email' => ['required', 'email:rfc', 'max:255'],
            'incident_reference' => ['required', 'string', 'max:100'],
            'reason' => ['required', 'string', 'max:1000'],
        ]);

        if ($validator->fails()) {
            foreach ($validator->errors()->all() as $error) {
                $this->error($error);
            }

            return self::FAILURE;
        }

        if (! hash_equals('RECOVER '.$email, $confirmation)) {
            $this->error('Confirmation did not match exactly.');

            return self::FAILURE;
        }

        $recovered = DB::transaction(function () use ($email, $incidentReference, $reason): ?User {
            $administrator = Role::query()
                ->where('code', 'administrator')
                ->lockForUpdate()
                ->firstOrFail();
            $user = User::query()->where('email', $email)->lockForUpdate()->first();

            if (! $user instanceof User) {
                return null;
            }

            $state = UserState::from((string) $user->getRawOriginal('state'));

            if (in_array($state, [UserState::Suspended, UserState::Deactivated], true)) {
                return null;
            }

            $assignment = RoleAssignment::query()
                ->where('user_id', $user->id)
                ->where('role_id', $administrator->id)
                ->whereNull('application_id')
                ->whereNull('revoked_at')
                ->where('starts_at', '<=', now())
                ->where(static function ($query): void {
                    $query->whereNull('ends_at')->orWhere('ends_at', '>', now());
                })
                ->lockForUpdate()
                ->first();

            if (! $assignment instanceof RoleAssignment) {
                return null;
            }

            $methods = UserMfaMethod::query()
                ->where('user_id', $user->id)
                ->orderBy('id')
                ->lockForUpdate()
                ->get();

            foreach ($methods as $method) {
                $method->recoveryCodes()->delete();
                $method->forceFill(['disabled_at' => now()])->save();
            }

            AuthChallenge::query()
                ->where('user_id', $user->id)
                ->whereNull('consumed_at')
                ->whereNull('invalidated_at')
                ->update(['invalidated_at' => now()]);
            PendingAuthentication::query()
                ->where('user_id', $user->id)
                ->whereNull('completed_at')
                ->whereNull('invalidated_at')
                ->update(['invalidated_at' => now()]);
            $sessionIds = AuthSession::query()
                ->where('user_id', $user->id)
                ->lockForUpdate()
                ->pluck('session_id');
            DB::table('sessions')->whereIn('id', $sessionIds)->delete();
            AuthSession::query()->where('user_id', $user->id)->delete();
            $user->forceFill([
                'state' => UserState::Invited,
                'email_verified_at' => null,
                'activated_at' => null,
                'invited_at' => now(),
                'invitation_expires_at' => now()->addDays((int) config('identity.invitation_ttl_days')),
                'session_version' => $user->session_version + 1,
            ])->save();
            $this->events->security(
                'identity.administrator.recovered',
                null,
                $user,
                ['incident_reference' => $incidentReference, 'reason' => $reason],
                null,
                'artisan',
                null,
            );
            DB::afterCommit(static fn () => $user->notify(new AdministratorRecoveryNotification));

            return $user;
        }, 3);

        if (! $recovered instanceof User) {
            $this->error('The target is not an eligible administrator principal.');

            return self::FAILURE;
        }

        $this->info('Administrator recovery was initiated and the registered address was notified.');

        return self::SUCCESS;
    }
}
