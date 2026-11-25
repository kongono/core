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
        private readonly int $maxInMemoryRecords = 1000,
    ) {
        $this->minSeverity = self::SEVERITY[strtolower($minLevel)] ?? 100;
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

        $safeContext = $this->scrubContext($context);
        $interpolated = SecretScrubber::scrub($this->interpolate((string) $message, $safeContext));
        $sanitizedMessage = self::stripAnsi($interpolated);

        $record = [
            'timestamp' => gmdate(DATE_ATOM),
            'level' => $levelStr,
            'channel' => $this->channel,
            'message' => $sanitizedMessage,
            'context' => $safeContext,
        ];

        if ($this->retainInMemory) {
            if ($this->maxInMemoryRecords > 0 && count($this->records) >= $this->maxInMemoryRecords) {
                array_shift($this->records);
            }
            $this->records[] = $record;
        }

        if (is_resource($this->stream)) {
            fwrite(
                $this->stream,
                json_encode($record, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n",
            );
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
    private function scrubContext(array $context, int $depth = 0): array
    {
        if ($depth >= 16) {
            return ['_truncated' => '[MAX_DEPTH]'];
        }

        $clean = [];
        foreach ($context as $key => $value) {
            $strKey = (string) $key;
            $safeKey = self::stripAnsi(SecretScrubber::scrub($strKey));
            if (SecretScrubber::isSensitiveKey($strKey)) {
                $clean[$safeKey] = '[REDACTED]';
                continue;
            }
            if (is_string($value)) {
                $clean[$safeKey] = self::stripAnsi(SecretScrubber::scrub($value));
            } elseif (is_array($value)) {
                $clean[$safeKey] = $this->scrubContext($value, $depth + 1);
            } elseif (is_float($value) && !is_finite($value)) {
                $clean[$safeKey] = is_nan($value) ? 'NAN' : ($value > 0 ? 'INF' : '-INF');
            } elseif (is_scalar($value) || null === $value) {
                $clean[$safeKey] = $value;
            } elseif ($value instanceof \Throwable) {
                $clean[$safeKey] = self::stripAnsi(sprintf('[%s] %s', $value::class, SecretScrubber::scrub($value->getMessage())));
            } elseif ($value instanceof Stringable) {
                $clean[$safeKey] = self::stripAnsi(SecretScrubber::scrub((string) $value));
            } else {
                $clean[$safeKey] = get_debug_type($value);
            }
        }

        return $clean;
    }

    private static function stripAnsi(string $text): string
    {
        // Strip 7-bit/8-bit OSC (\e] / U+009D), DCS/SOS/PM/APC (\e[PX^_] / C1), ECMA-48 CSI (\e[ / U+009B), 2-byte ESC, and remaining C1/ESC bytes
        $cleaned = (string) preg_replace('/(?:\x1b\]|\xC2\x9D)[\s\S]*?(?:\x07|\x1b\\\\|\xC2\x9C|\z)/', '', $text);
        $cleaned = (string) preg_replace('/(?:\x1b[PX^_]|\xC2[\x90\x98\x9E\x9F])[\s\S]*?(?:\x1b\\\\|\xC2\x9C|\z)/', '', $cleaned);
        $cleaned = (string) preg_replace('/(?:\x1b\[|\xC2\x9B)[0-9:;<=>?]*[ -\/]*[@-~]/', '', $cleaned);

        return (string) preg_replace('/\x1b[@-Z\\\\-_]|\x1b|\xC2[\x80-\x9F]/', '', $cleaned);
    }
}
