<?php

declare(strict_types=1);

namespace Kongono\Core\Telemetry;

use Closure;

/**
 * Operation-scoped performance tracer with nanosecond hrtime() spans
 * and standard HTTP `Server-Timing` header emission.
 */
final class Tracer
{
    /** @var list<array{name: string, duration_ms: float}> */
    private array $spans = [];

    /**
     * Measure a named span and return its callback's result.
     *
     * @template T
     * @param Closure(): T $callback
     * @return T
     */
    public function span(string $name, Closure $callback): mixed
    {
        $start = hrtime(true);

        try {
            return $callback();
        } finally {
            $elapsedMs = (hrtime(true) - $start) / 1_000_000;
            $this->spans[] = ['name' => $name, 'duration_ms' => $elapsedMs];
        }
    }

    /** @return list<array{name: string, duration_ms: float}> */
    public function spans(): array
    {
        return $this->spans;
    }

    /** Format all recorded spans into a standard RFC Server-Timing HTTP header value. */
    public function toServerTimingHeader(): string
    {
        $parts = [];
        foreach ($this->spans as $span) {
            $token = (string) preg_replace('/[^a-zA-Z0-9_-]/', '_', $span['name']);
            $parts[] = sprintf('%s;dur=%.2f', '' !== $token ? $token : 'span', $span['duration_ms']);
        }

        return implode(', ', $parts);
    }

    public function reset(): void
    {
        $this->spans = [];
    }
}
