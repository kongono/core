<?php

declare(strict_types=1);

namespace Kongono\Core;

use Closure;
use SplObjectStorage;

/**
 * Persistent-runtime-first lifecycle state machine.
 *
 * Designed for both traditional PHP-FPM and long-lived workers (FrankenPHP, RoadRunner, CLI).
 * Tracks active operation scopes explicitly and guarantees LIFO cleanup per operation.
 */
final class Kernel
{
    private KernelState $state = KernelState::Unbooted;

    /** @var SplObjectStorage<OperationScope, null> */
    private SplObjectStorage $activeScopes;

    private int $sequence = 0;

    public function __construct()
    {
        $this->activeScopes = new SplObjectStorage();
    }

    public function state(): KernelState
    {
        return $this->state;
    }

    public function boot(): void
    {
        if (KernelState::Unbooted !== $this->state) {
            throw new CoreException(sprintf('Cannot boot kernel from state "%s".', $this->state->value));
        }
        $this->state = KernelState::Booted;
    }

    public function shutdown(): void
    {
        if (KernelState::Booted !== $this->state) {
            throw new CoreException(sprintf('Cannot shut down kernel from state "%s".', $this->state->value));
        }
        if ($this->activeScopes->count() > 0) {
            throw new CoreException(sprintf('Cannot shut down kernel while %d operation(s) are still active.', $this->activeScopes->count()));
        }
        $this->state = KernelState::Shutdown;
    }

    public function beginOperation(?string $id = null): OperationScope
    {
        if (KernelState::Booted !== $this->state) {
            throw new CoreException(sprintf('Cannot begin operation while kernel is "%s".', $this->state->value));
        }
        ++$this->sequence;
        $scope = new OperationScope($id ?? sprintf('op-%d', $this->sequence));
        $this->activeScopes[$scope] = null;

        return $scope;
    }

    public function endOperation(OperationScope $scope): void
    {
        if (!isset($this->activeScopes[$scope])) {
            throw new CoreException('Operation scope is not active or does not belong to this kernel.');
        }
        unset($this->activeScopes[$scope]);
        $scope->end();
    }

    /**
     * Runs a callback inside an isolated operation scope and always cleans it up.
     *
     * @template T
     * @param Closure(OperationScope): T $callback
     * @return T
     */
    public function runOperation(Closure $callback, ?string $id = null): mixed
    {
        $scope = $this->beginOperation($id);

        try {
            return $callback($scope);
        } finally {
            $this->endOperation($scope);
        }
    }

    public function activeOperationCount(): int
    {
        return $this->activeScopes->count();
    }
}
