<?php

declare(strict_types=1);

namespace Kongono\Core\Telemetry;

/**
 * Lightweight, zero-dependency, persistent-runtime-safe metrics registry
 * with native Prometheus text exposition format (`/metrics`).
 */
final class Metrics
{
    /** @var array<string, array{name: string, labels: array<string, string>, value: float}> */
    private array $counters = [];

    /** @var array<string, array{name: string, labels: array<string, string>, value: float}> */
    private array $gauges = [];

    /** @var array<string, array{name: string, labels: array<string, string>, count: int, sum: float, max: float}> */
    private array $timings = [];

    /** @param array<string, string> $labels */
    public function increment(string $name, array $labels = [], float $by = 1.0): void
    {
        $key = $this->seriesKey($name, $labels);
        if (!isset($this->counters[$key])) {
            $this->counters[$key] = ['name' => $name, 'labels' => $labels, 'value' => 0.0];
        }
        $this->counters[$key]['value'] += $by;
    }

    /** @param array<string, string> $labels */
    public function gauge(string $name, float $value, array $labels = []): void
    {
        $key = $this->seriesKey($name, $labels);
        $this->gauges[$key] = ['name' => $name, 'labels' => $labels, 'value' => $value];
    }

    /** @param array<string, string> $labels */
    public function observe(string $name, float $value, array $labels = []): void
    {
        $key = $this->seriesKey($name, $labels);
        if (!isset($this->timings[$key])) {
            $this->timings[$key] = ['name' => $name, 'labels' => $labels, 'count' => 0, 'sum' => 0.0, 'max' => $value];
        }
        ++$this->timings[$key]['count'];
        $this->timings[$key]['sum'] += $value;
        if ($value > $this->timings[$key]['max']) {
            $this->timings[$key]['max'] = $value;
        }
    }

    /** @param array<string, string> $labels */
    public function counterValue(string $name, array $labels = []): float
    {
        return $this->counters[$this->seriesKey($name, $labels)]['value'] ?? 0.0;
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
    private function formatLabels(array $labels): string
    {
        if ([] === $labels) {
            return '';
        }
        ksort($labels);
        $parts = [];
        foreach ($labels as $k => $v) {
            $escaped = str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $v);
            $parts[] = sprintf('%s="%s"', $k, $escaped);
        }

        return '{' . implode(',', $parts) . '}';
    }

    private function formatFloat(float $value): string
    {
        return floor($value) === $value ? (string) (int) $value : sprintf('%.6F', $value);
    }
}
