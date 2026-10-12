<?php

declare(strict_types=1);

namespace App\Services\Identity;

use App\Models\User;
use App\Support\Exceptions\DomainRuleViolation;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;
use WeakMap;

final class IdentityMutationBoundary
{
    /** @var WeakMap<Throwable, bool> */
    private WeakMap $recorded;

    public function __construct(private readonly IdentityEventRecorder $events)
    {
        $this->recorded = new WeakMap;
    }

    /**
     * @template T
     *
     * @param  callable(): T  $mutation
     * @return T
     */
    public function run(
        callable $mutation,
        User $actor,
        string $action,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        ?string $correlationId = null,
    ): mixed {
        try {
            return $mutation();
        } catch (AuthorizationException|DomainRuleViolation $exception) {
            $this->record($exception, $actor, $action, $ipAddress, $userAgent, $correlationId);
            throw $exception;
        }
    }

    public function record(
        Throwable $exception,
        ?User $actor,
        string $action,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        ?string $correlationId = null,
    ): void {
        if (isset($this->recorded[$exception])) {
            return;
        }
        $reason = $exception instanceof DomainRuleViolation ? $exception->ruleCode : 'permission_denied';
        $selfMutation = in_array($reason, [
            'self_role_assignment', 'actor_assigned_role_edit', 'actor_assigned_role_activation', 'self_mfa_reset',
        ], true);
        if (! $selfMutation && ! $exception instanceof AuthorizationException
            && ! in_array($reason, ['unauthorized_mfa_reset', 'fresh_mfa_required'], true)) {
            return;
        }
        $this->recorded[$exception] = true;
        $requestCorrelation = request()->attributes->get('correlation_id');
        $correlationId ??= is_string($requestCorrelation) ? $requestCorrelation : (string) Str::uuid();
        $written = false;
        $write = function () use (&$written, $actor, $action, $ipAddress, $userAgent, $correlationId, $reason, $selfMutation): void {
            if ($written) {
                return;
            }
            $persistedActor = $actor === null ? null : User::withTrashed()->whereKey($actor->getKey())->first();
            $this->events->security(
                $selfMutation ? 'identity.self_escalation.rejected' : 'identity.authorization.denied',
                $persistedActor,
                $selfMutation ? $persistedActor : null,
                ['action' => $action, 'reason' => $reason, 'actor_public_id' => $actor?->public_id],
                $ipAddress ?? request()->ip(),
                $userAgent ?? request()->userAgent(),
                $correlationId,
            );
            $written = true;
        };

        if (DB::transactionLevel() === 0) {
            $write();

            return;
        }

        // Attach to the outer transaction: an inner rollback must not write an event
        // into a still-open transaction that could subsequently erase it.
        /** @var DatabaseTransactionsManager $transactions */
        $transactions = app('db.transactions');
        $root = $transactions->callbackApplicableTransactions()
            ->first(fn ($transaction): bool => $transaction->connection === DB::connection()->getName());
        if ($root !== null) {
            $root->addCallback($write);
            $root->addCallbackForRollback($write);
        } else {
            $write();
        }
    }
}
