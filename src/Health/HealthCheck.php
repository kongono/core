<?php

declare(strict_types=1);

namespace Kongono\Core\Health;

use Closure;
use Kongono\Core\Diagnostics\SecretScrubber;
use Throwable;

/** Composable readiness & liveness health checker with nondisclosing error defaults and per-check latency reporting. */
final class HealthCheck
{
    /** @var array<string, Closure(): bool> */
    private array $checks = [];

    public function __construct(
        private readonly bool $exposeErrors = false,
    ) {}

    /** @param Closure(): bool $probe Return true if healthy; throw or return false if unhealthy */
    public function check(string $name, Closure $probe): self
    {
        $this->checks[$name] = $probe;

        return $this;
    }

    /**
     * Evaluate all registered checks and return a structured health report.
     *
     * @return array{
     *     status: 'ok'|'degraded',
     *     healthy: bool,
     *     timestamp: string,
     *     checks: array<string, array{ok: bool, duration_ms: float, error?: string}>
     * }
     */
    public function run(?bool $exposeErrors = null): array
    {
        $reveal = $exposeErrors ?? $this->exposeErrors;
        $allHealthy = true;
        $results = [];

        foreach ($this->checks as $name => $probe) {
            $start = hrtime(true);
            try {
                $ok = $probe();
                $durationMs = round((hrtime(true) - $start) / 1_000_000, 2);
                $results[$name] = ['ok' => $ok, 'duration_ms' => $durationMs];
                if (!$ok) {
                    $allHealthy = false;
                }
            } catch (Throwable $e) {
                $durationMs = round((hrtime(true) - $start) / 1_000_000, 2);
                $allHealthy = false;
                $results[$name] = [
                    'ok' => false,
                    'duration_ms' => $durationMs,
                    'error' => $reveal ? SecretScrubber::scrub($e->getMessage()) : 'Health check failed.',
                ];
            }
        }

        return [
            'status' => $allHealthy ? 'ok' : 'degraded',
            'healthy' => $allHealthy,
            'timestamp' => gmdate(DATE_ATOM),
            'checks' => $results,
        ];
    }
}
