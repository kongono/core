<?php

declare(strict_types=1);

namespace Kongono\Core\Resilience;

use Closure;
use Throwable;

/** Exponential backoff retry helper with optional predicate and deterministic test sleeper. */
final class Retry
{
    /**
     * Execute $operation with exponential backoff retries.
     *
     * @template T
     * @param Closure(int): T                $operation   Receives 1-based attempt number
     * @param positive-int                   $maxAttempts
     * @param non-negative-int               $baseDelayMs
     * @param (Closure(Throwable): bool)|null $shouldRetry Return false to abort retries immediately
     * @param (Closure(int): void)|null      $sleeper     Custom delay callback receiving milliseconds (default usleep)
     * @return T
     */
    public static function run(
        Closure $operation,
        int $maxAttempts = 3,
        int $baseDelayMs = 100,
        ?Closure $shouldRetry = null,
        ?Closure $sleeper = null,
    ): mixed {
        $attempt = 0;
        while (true) {
            ++$attempt;

            try {
                return $operation($attempt);
            } catch (Throwable $e) {
                if ($attempt >= $maxAttempts || (null !== $shouldRetry && !$shouldRetry($e))) {
                    throw $e;
                }

                $delayMs = $baseDelayMs * (2 ** ($attempt - 1));
                if (null !== $sleeper) {
                    $sleeper($delayMs);
                } elseif ($delayMs > 0) {
                    usleep($delayMs * 1000);
                }
            }
        }
    }
}
