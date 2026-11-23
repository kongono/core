<?php

declare(strict_types=1);

namespace Kongono\Core\Clock;

use DateTimeImmutable;

/**
 * Pure DI clock contract (method-compatible with PSR-20) with zero global static state.
 * Bind SystemClock in production and FrozenClock in tests for deterministic time travel.
 */
interface ClockInterface
{
    public function now(): DateTimeImmutable;

    public function timestamp(): int;
}
