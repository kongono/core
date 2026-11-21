<?php

declare(strict_types=1);

namespace Kongono\Core;

/** Strict, zero-dependency .env file loader (never overwrites existing environment variables by default). */
final class EnvLoader
{
    /**
     * Load key=value pairs from a .env file into $_ENV and $_SERVER.
     *
     * @return array<string, string> Loaded variables
     */
    public static function load(string $filePath, bool $overwrite = false): array
    {
        if (!is_file($filePath)) {
            return [];
        }
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (false === $lines) {
            return [];
        }

        $loaded = [];
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ('' === $trimmed || str_starts_with($trimmed, '#')) {
                continue;
            }
            if (str_starts_with($trimmed, 'export ')) {
                $trimmed = trim(substr($trimmed, 7));
            }
            $pos = strpos($trimmed, '=');
            if (false === $pos) {
                continue;
            }

            $key = trim(substr($trimmed, 0, $pos));
            if ('' === $key || 1 !== preg_match('/\A[A-Z0-9_]+\z/i', $key)) {
                continue;
            }

            $rawValue = trim(substr($trimmed, $pos + 1));
            $value = self::parseValue($rawValue);

            if (!$overwrite && (array_key_exists($key, $_ENV) || false !== getenv($key))) {
                continue;
            }

            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
            putenv($key . '=' . $value);
            $loaded[$key] = $value;
        }

        return $loaded;
    }

    private static function parseValue(string $raw): string
    {
        if (strlen($raw) >= 2) {
            $first = $raw[0];
            $last = $raw[strlen($raw) - 1];
            if (('"' === $first && '"' === $last) || ("'" === $first && "'" === $last)) {
                $inner = substr($raw, 1, -1);

                return '"' === $first
                    ? str_replace(['\\n', '\\r', '\\t', '\\"', '\\\\'], ["\n", "\r", "\t", '"', '\\'], $inner)
                    : $inner;
            }
        }

        // Strip inline comments on unquoted values
        $hashPos = strpos($raw, ' #');
        if (false !== $hashPos) {
            return trim(substr($raw, 0, $hashPos));
        }

        return $raw;
    }
}
