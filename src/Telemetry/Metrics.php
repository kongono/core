<?php

declare(strict_types=1);

namespace Kongono\Core\Telemetry;

use Kongono\Core\CoreException;

/**
 * Lightweight, zero-dependency, persistent-runtime-safe metrics registry
 * with bounded cardinality and hardened Prometheus text exposition format (`/metrics`).
 */
final class Metrics
{
    /** @var array<string, array{name: string, labels: array<string, string>, value: float}> */
    private array $counters = [];

    /** @var array<string, array{name: string, labels: array<string, string>, value: float}> */
    private array $gauges = [];

    /** @var array<string, array{name: string, labels: array<string, string>, count: int, sum: float, max: float}> */
    private array $timings = [];

    /** @param positive-int $maxSeries Maximum tracked series per metric kind (prevents worker OOM) */
    public function __construct(
        private readonly int $maxSeries = 4096,
    ) {}

    /** @param array<string, string> $labels */
    public function increment(string $name, array $labels = [], float $by = 1.0): void
    {
        self::assertValidMetric($name, $labels);
        $key = $this->seriesKey($name, $labels);
        if (!isset($this->counters[$key])) {
            if (count($this->counters) >= $this->maxSeries) {
                return;
            }
            $this->counters[$key] = ['name' => $name, 'labels' => $labels, 'value' => 0.0];
        }
        $this->counters[$key]['value'] += $by;
    }

    /** @param array<string, string> $labels */
    public function gauge(string $name, float $value, array $labels = []): void
    {
        self::assertValidMetric($name, $labels);
        $key = $this->seriesKey($name, $labels);
        if (!isset($this->gauges[$key]) && count($this->gauges) >= $this->maxSeries) {
            return;
        }
        $this->gauges[$key] = ['name' => $name, 'labels' => $labels, 'value' => $value];
    }

    /** @param array<string, string> $labels */
    public function observe(string $name, float $value, array $labels = []): void
    {
        self::assertValidMetric($name, $labels);
        $key = $this->seriesKey($name, $labels);
        if (!isset($this->timings[$key])) {
            if (count($this->timings) >= $this->maxSeries) {
                return;
            }
            $this->timings[$key] = ['name' => $name, 'labels' => $labels, 'count' => 0, 'sum' => 0.0, 'max' => $value];
        }
        ++$this->timings[$key]['count'];
        $this->timings[$key]['sum'] += $value;
        if ($value > $this->timings[$key]['max']) {
            $this->timings[$key]['max'] = $value;
        }
    }

    public function reset(): void
    {
        $this->counters = [];
        $this->gauges = [];
        $this->timings = [];
    }

    /** @param array<string, string> $labels */
    public function counterValue(string $name, array $labels = []): float
    {
        return $this->counters[$this->seriesKey($name, $labels)]['value'] ?? 0.0;
    }

    /**
     * Return a structured snapshot of all tracked counters, gauges, and timings (ideal for OpsDashboard / JSON APIs).
     *
     * @return array{
     *     counters: list<array{name: string, labels: array<string, string>, value: float}>,
     *     gauges: list<array{name: string, labels: array<string, string>, value: float}>,
     *     timings: list<array{name: string, labels: array<string, string>, count: int, sum: float, max: float, avg: float}>
     * }
     */
    public function snapshot(): array
    {
        $timings = [];
        foreach ($this->timings as $t) {
            $timings[] = [
                'name' => $t['name'],
                'labels' => $t['labels'],
                'count' => $t['count'],
                'sum' => round($t['sum'], 4),
                'max' => round($t['max'], 4),
                'avg' => $t['count'] > 0 ? round($t['sum'] / $t['count'], 4) : 0.0,
            ];
        }

        return [
            'counters' => array_values($this->counters),
            'gauges' => array_values($this->gauges),
            'timings' => $timings,
        ];
    }

    /** Export all metrics in standard Prometheus text exposition format 0.0.4. */
    public function toPrometheus(): string
    {
        $lines = [];
        foreach ($this->counters as $series) {
            $lines[] = sprintf('%s%s %s', $series['name'], $this->formatLabels($series['labels']), $this->formatFloat($series['value']));
        }
        foreach ($this->gauges as $series) {
            $lines[] = sprintf('%s%s %s', $series['name'], $this->formatLabels($series['labels']), $this->formatFloat($series['value']));
        }
        foreach ($this->timings as $series) {
            $lbl = $this->formatLabels($series['labels']);
            $lines[] = sprintf('%s_count%s %d', $series['name'], $lbl, $series['count']);
            $lines[] = sprintf('%s_sum%s %s', $series['name'], $lbl, $this->formatFloat($series['sum']));
            $lines[] = sprintf('%s_max%s %s', $series['name'], $lbl, $this->formatFloat($series['max']));
        }

        sort($lines, SORT_STRING);

        return implode("\n", $lines) . ('' !== implode('', $lines) ? "\n" : '');
    }

    /** @param array<string, string> $labels */
    private function seriesKey(string $name, array $labels): string
    {
        ksort($labels);

        return $name . '|' . json_encode($labels, JSON_THROW_ON_ERROR);
    }

    /** @param array<string, string> $labels */
    private static function assertValidMetric(string $name, array $labels): void
    {
        if (1 !== preg_match('/\A[a-zA-Z_:][a-zA-Z0-9_:]*\z/', $name)) {
            throw new CoreException(sprintf('Invalid Prometheus metric name "%s".', $name));
        }
        foreach (array_keys($labels) as $labelName) {
            if (1 !== preg_match('/\A[a-zA-Z_][a-zA-Z0-9_]*\z/', $labelName)) {
                throw new CoreException(sprintf('Invalid Prometheus label name "%s".', $labelName));
            }
        }
    }

    /** @param array<string, string> $labels */
    private function formatLabels(array $labels): string
    {
        if ([] === $labels) {
            return '';
        }
        ksort($labels);
        $parts = [];
        foreach ($labels as $k => $v) {
            $escaped = str_replace(['\\', '"', "\n", "\r"], ['\\\\', '\\"', '\\n', '\\r'], $v);
            $parts[] = sprintf('%s="%s"', $k, $escaped);
        }

        return '{' . implode(',', $parts) . '}';
    }

    private function formatFloat(float $value): string
    {
        return floor($value) === $value ? (string) (int) $value : sprintf('%.6F', $value);
    }
}
