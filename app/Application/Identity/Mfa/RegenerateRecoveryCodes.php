<?php

declare(strict_types=1);

namespace App\Application\Identity\Mfa;

use App\Domain\Identity\Enums\MfaMethodType;
use App\Models\User;
use App\Models\UserMfaMethod;
use App\Models\UserRecoveryCode;
use App\Notifications\Identity\RecoveryCodesRegeneratedNotification;
use App\Services\Identity\CurrentAuthSessionValidator;
use App\Services\Identity\IdentityEventRecorder;
use App\Services\Identity\IdentityMutationBoundary;
use App\Services\Identity\RecoveryCodeHasher;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Support\Facades\DB;

final class RegenerateRecoveryCodes
{
    private const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    public function __construct(private readonly IdentityMutationBoundary $mutationBoundary,
        private readonly CurrentAuthSessionValidator $sessions,
        private readonly RecoveryCodeHasher $hasher,
        private readonly IdentityEventRecorder $events,
    ) {}

    /** @return list<string> */
    public function handle(User $user, ?string $ipAddress, ?string $userAgent, ?string $correlationId): array
    {
        return $this->mutationBoundary->run(function () use ($user, $ipAddress, $userAgent, $correlationId): array {
            return DB::transaction(function () use ($user, $ipAddress, $userAgent, $correlationId): array {
                $lockedUser = User::query()->whereKey($user->id)->lockForUpdate()->firstOrFail();
                $this->assertFreshMfa($lockedUser);
                $method = UserMfaMethod::query()
                    ->where('user_id', $lockedUser->id)
                    ->where('type', MfaMethodType::Totp)
                    ->whereNotNull('confirmed_at')
                    ->whereNull('disabled_at')
                    ->lockForUpdate()
                    ->firstOrFail();
                $method->recoveryCodes()->delete();
                $codes = [];

                for ($index = 0; $index < (int) config('identity.totp.recovery_code_count'); $index++) {
                    $plain = $this->generate((int) config('identity.totp.recovery_code_length'));
                    UserRecoveryCode::query()->create([
                        'user_mfa_method_id' => $method->id,
                        'code_hmac' => $this->hasher->hash($plain, $method->id),
                    ]);
                    $codes[] = $plain;
                }

                $this->events->security(
                    'identity.recovery_codes.regenerated',
                    $lockedUser,
                    $lockedUser,
                    ['count' => count($codes)],
                    $ipAddress,
                    $userAgent,
                    $correlationId,
                );
                DB::afterCommit(static fn () => $lockedUser->notify(new RecoveryCodesRegeneratedNotification));

                return $codes;
            }, 3);
        }, $user, self::class, $ipAddress, $userAgent, $correlationId);
    }

    private function assertFreshMfa(User $user): void
    {
        if (! $this->sessions->hasFreshMfa($user)) {
            throw new DomainRuleViolation('fresh_mfa_required', ['Fresh email and MFA authentication is required.']);
        }
    }

    private function generate(int $length): string
    {
        $plain = '';
        $max = strlen(self::ALPHABET) - 1;

        for ($index = 0; $index < $length; $index++) {
            $plain .= self::ALPHABET[random_int(0, $max)];
        }

        return implode('-', str_split($plain, 4));
    }
}
