<?php

declare(strict_types=1);

namespace Kongono\Core\Clock;

use DateTimeImmutable;
use DateTimeZone;
use Kongono\Core\CoreException;

/**
 * Deterministic, instance-scoped test clock (zero static globals, safe for persistent runtimes
 * and parallel test execution).
 */
final class FrozenClock implements ClockInterface
{
    private DateTimeImmutable $current;
    private readonly DateTimeZone $timezone;

    public function __construct(
        DateTimeImmutable|int|string $at = 'now',
        ?DateTimeZone $timezone = null,
    ) {
        $this->timezone = $timezone ?? ($at instanceof DateTimeImmutable ? $at->getTimezone() : new DateTimeZone('UTC'));
        $this->current = $this->normalize($at);
    }

    public static function at(DateTimeImmutable|int|string $at, ?DateTimeZone $timezone = null): self
    {
        return new self($at, $timezone);
    }

    public function now(): DateTimeImmutable
    {
        return $this->current;
    }

    public function timestamp(): int
    {
        return $this->current->getTimestamp();
    }

    public function freeze(DateTimeImmutable|int|string $at): self
    {
        $this->current = $this->normalize($at);

        return $this;
    }

    public function advanceSeconds(int $seconds): self
    {
        return $this->modify(($seconds >= 0 ? '+' : '') . $seconds . ' seconds');
    }

    public function advanceMinutes(int $minutes): self
    {
        return $this->advanceSeconds($minutes * 60);
    }

    public function advanceHours(int $hours): self
    {
        return $this->advanceSeconds($hours * 3600);
    }

    public function advanceDays(int $days): self
    {
        return $this->advanceSeconds($days * 86_400);
    }

    public function rewindSeconds(int $seconds): self
    {
        return $this->advanceSeconds(-$seconds);
    }

    public function modify(string $modifier): self
    {
        try {
            $this->current = $this->current->modify($modifier);
        } catch (\Throwable $e) {
            throw new CoreException(sprintf('Invalid clock modifier "%s".', $modifier), previous: $e);
        }

        return $this;
    }

    private function normalize(DateTimeImmutable|int|string $at): DateTimeImmutable
    {
        if ($at instanceof DateTimeImmutable) {
            return $at->setTimezone($this->timezone);
        }
        if (is_int($at)) {
            return (new DateTimeImmutable('@' . $at))->setTimezone($this->timezone);
        }

        try {
            return new DateTimeImmutable($at, $this->timezone);
        } catch (\Throwable $e) {
            throw new CoreException(sprintf('Invalid clock timestamp "%s".', $at), previous: $e);
        }
    }
}
