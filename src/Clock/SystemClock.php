<?php

declare(strict_types=1);

namespace Kongono\Core\Clock;

use DateTimeImmutable;
use DateTimeZone;

/** Production wall-clock implementation defaulting to UTC. */
final readonly class SystemClock implements ClockInterface
{
    private DateTimeZone $timezone;

    public function __construct(?DateTimeZone $timezone = null)
    {
        $this->timezone = $timezone ?? new DateTimeZone('UTC');
    }

    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', $this->timezone);
    }

    public function timestamp(): int
    {
        return $this->now()->getTimestamp();
    }
}
