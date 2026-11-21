<?php

declare(strict_types=1);

namespace Kongono\Core\Log;

use Kongono\Core\Diagnostics\SecretScrubber;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Stringable;

/**
 * Structured JSON PSR-3 logger with automatic SecretScrubber redaction.
 * Writes NDJSON lines to a stream or collects records in memory for tests.
 */
final class Logger extends AbstractLogger
{
    private const array SEVERITY = [
        LogLevel::DEBUG => 100,
        LogLevel::INFO => 200,
        LogLevel::NOTICE => 250,
        LogLevel::WARNING => 300,
        LogLevel::ERROR => 400,
        LogLevel::CRITICAL => 500,
        LogLevel::ALERT => 550,
        LogLevel::EMERGENCY => 600,
    ];

    /** @var list<array{timestamp: string, level: string, channel: string, message: string, context: array<string, mixed>}> */
    private array $records = [];

    private int $minSeverity;

    /** @param resource|null $stream Optional output stream (e.g. STDERR or file handle) */
    public function __construct(
        private readonly string $channel = 'kongono',
        string $minLevel = LogLevel::DEBUG,
        private readonly mixed $stream = null,
        private readonly bool $retainInMemory = false,
    ) {
        $this->minSeverity = self::SEVERITY[$minLevel] ?? 100;
    }

    /**
     * @param mixed                $level
     * @param array<array-key, mixed> $context
     */
    public function log($level, string|Stringable $message, array $context = []): void
    {
        $levelStr = is_string($level) ? strtolower($level) : LogLevel::INFO;
        $severity = self::SEVERITY[$levelStr] ?? 200;
        if ($severity < $this->minSeverity) {
            return;
        }

        $interpolated = SecretScrubber::scrub($this->interpolate((string) $message, $context));
        $safeContext = $this->scrubContext($context);

        $record = [
            'timestamp' => gmdate(DATE_ATOM),
            'level' => $levelStr,
            'channel' => $this->channel,
            'message' => $interpolated,
            'context' => $safeContext,
        ];

        if ($this->retainInMemory) {
            $this->records[] = $record;
        }

        if (is_resource($this->stream)) {
            fwrite($this->stream, json_encode($record, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
        }
    }

    /** @return list<array{timestamp: string, level: string, channel: string, message: string, context: array<string, mixed>}> */
    public function records(): array
    {
        return $this->records;
    }

    public function clearRecords(): void
    {
        $this->records = [];
    }

    /** @param array<array-key, mixed> $context */
    private function interpolate(string $message, array $context): string
    {
        $replace = [];
        foreach ($context as $key => $val) {
            if (is_string($key) && (is_scalar($val) || $val instanceof Stringable)) {
                $replace['{' . $key . '}'] = (string) $val;
            }
        }

        return strtr($message, $replace);
    }

    /**
     * @param array<array-key, mixed> $context
     * @return array<string, mixed>
     */
    private function scrubContext(array $context): array
    {
        $clean = [];
        foreach ($context as $key => $value) {
            $strKey = (string) $key;
            if (1 === preg_match('/password|secret|token|authorization|api_?key/i', $strKey)) {
                $clean[$strKey] = '[REDACTED]';
                continue;
            }
            if (is_string($value)) {
                $clean[$strKey] = SecretScrubber::scrub($value);
            } elseif (is_array($value)) {
                $clean[$strKey] = $this->scrubContext($value);
            } elseif (is_scalar($value) || null === $value) {
                $clean[$strKey] = $value;
            } else {
                $clean[$strKey] = get_debug_type($value);
            }
        }

        return $clean;
    }
}
