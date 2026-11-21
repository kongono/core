<?php

declare(strict_types=1);

namespace Kongono\Core\Resilience;

use Closure;
use Kongono\Core\CoreException;
use Throwable;

/**
 * Persistent-runtime-safe Circuit Breaker protecting downstream APIs, databases, and AI providers
 * from cascading failures (`Closed` -> `Open` -> `HalfOpen`).
 */
final class CircuitBreaker
{
    private CircuitState $state = CircuitState::Closed;
    private int $consecutiveFailures = 0;
    private ?int $openedAt = null;

    /**
     * @param positive-int $failureThreshold       Consecutive failures before tripping Open
     * @param positive-int $recoveryTimeoutSeconds Cooldown before allowing a Half-Open probe
     */
    public function __construct(
        private readonly string $serviceName,
        private readonly int $failureThreshold = 5,
        private readonly int $recoveryTimeoutSeconds = 30,
    ) {}

    public function state(?int $now = null): CircuitState
    {
        if (CircuitState::Open === $this->state && null !== $this->openedAt) {
            if (($now ?? time()) - $this->openedAt >= $this->recoveryTimeoutSeconds) {
                return CircuitState::HalfOpen;
            }
        }

        return $this->state;
    }

    /**
     * Execute $operation guarded by this circuit breaker.
     *
     * @template T
     * @param Closure(): T $operation
     * @return T
     */
    public function call(Closure $operation, ?int $now = null): mixed
    {
        $ts = $now ?? time();
        $current = $this->state($ts);

        if (CircuitState::Open === $current) {
            throw new CoreException(sprintf('Circuit breaker for "%s" is OPEN; failing fast.', $this->serviceName));
        }

        try {
            $result = $operation();
            $this->recordSuccess();

            return $result;
        } catch (Throwable $e) {
            $this->recordFailure($ts);
            throw $e;
        }
    }

    public function recordSuccess(): void
    {
        $this->consecutiveFailures = 0;
        $this->openedAt = null;
        $this->state = CircuitState::Closed;
    }

    public function recordFailure(?int $now = null): void
    {
        ++$this->consecutiveFailures;
        if ($this->consecutiveFailures >= $this->failureThreshold || CircuitState::HalfOpen === $this->state($now)) {
            $this->state = CircuitState::Open;
            $this->openedAt = $now ?? time();
        }
    }

    public function consecutiveFailures(): int
    {
        return $this->consecutiveFailures;
    }
}
