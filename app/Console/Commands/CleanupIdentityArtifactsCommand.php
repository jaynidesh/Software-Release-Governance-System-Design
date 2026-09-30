<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\AuthChallenge;
use App\Models\PendingAuthentication;
use App\Models\UserMfaMethod;
use App\Services\Identity\AuthenticatedSessionManager;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;

final class CleanupIdentityArtifactsCommand extends Command
{
    protected $signature = 'identity:cleanup {--chunk=500 : Maximum records deleted per transaction}';

    protected $description = 'Remove expired transient identity records and orphaned session storage';

    public function __construct(private readonly AuthenticatedSessionManager $sessions)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $chunkSize = filter_var($this->option('chunk'), FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 10_000],
        ]);

        if (! is_int($chunkSize)) {
            $this->error('The chunk size must be an integer between 1 and 10000.');

            return self::FAILURE;
        }

        $retentionCutoff = now()->subHours((int) config('identity.challenge_retention_hours'));
        $pendingAuthentications = $this->deleteEloquentChunks(
            PendingAuthentication::query()
                ->where(static function (Builder $query) use ($retentionCutoff): void {
                    $query->where('expires_at', '<=', $retentionCutoff)
                        ->orWhere(static function (Builder $terminal) use ($retentionCutoff): void {
                            $terminal->where('updated_at', '<=', $retentionCutoff)
                                ->where(static function (Builder $state): void {
                                    $state->whereNotNull('completed_at')->orWhereNotNull('invalidated_at');
                                });
                        });
                }),
            $chunkSize,
        );
        $challenges = $this->deleteEloquentChunks(
            AuthChallenge::query()
                ->where(static function (Builder $query) use ($retentionCutoff): void {
                    $query->where('expires_at', '<=', $retentionCutoff)
                        ->orWhere(static function (Builder $terminal) use ($retentionCutoff): void {
                            $terminal->where('updated_at', '<=', $retentionCutoff)
                                ->where(static function (Builder $state): void {
                                    $state->whereNotNull('consumed_at')->orWhereNotNull('invalidated_at');
                                });
                        });
                })
                ->whereDoesntHave('pendingAuthentications'),
            $chunkSize,
        );
        $unconfirmedMfaMethods = $this->deleteEloquentChunks(
            UserMfaMethod::query()
                ->whereNull('confirmed_at')
                ->where('created_at', '<=', now()->subMinutes(
                    (int) config('identity.totp.unconfirmed_ttl_minutes'),
                )),
            $chunkSize,
        );
        $orphans = $this->sessions->purgeOrphans($chunkSize);

        $this->line("Expired pending authentications: {$pendingAuthentications}");
        $this->line("Expired authentication challenges: {$challenges}");
        $this->line("Abandoned unconfirmed MFA methods: {$unconfirmedMfaMethods}");
        $this->line("Orphan auth sessions: {$orphans['metadata']}");
        $this->line("Orphan session payloads: {$orphans['payloads']}");

        return self::SUCCESS;
    }

    /** @param Builder<*> $query */
    private function deleteEloquentChunks(Builder $query, int $chunkSize): int
    {
        $deleted = 0;

        do {
            $count = DB::transaction(function () use ($query, $chunkSize): int {
                $ids = (clone $query)->orderBy('id')->limit($chunkSize)->pluck('id');

                return $ids->isEmpty() ? 0 : (clone $query)->whereKey($ids)->delete();
            }, 3);
            $deleted += $count;
        } while ($count === $chunkSize);

        return $deleted;
    }
}
