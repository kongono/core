<?php

declare(strict_types=1);

namespace Kongono\Core;

/** Strict, zero-dependency .env file loader (never overwrites existing environment variables by default). */
final class EnvLoader
{
    /** @var list<string> */
    private const array FORBIDDEN_KEYS = [
        'REMOTE_ADDR',
        'REMOTE_HOST',
        'REMOTE_PORT',
        'HTTPS',
        'REQUEST_URI',
        'REQUEST_METHOD',
        'SCRIPT_FILENAME',
        'SCRIPT_NAME',
        'DOCUMENT_ROOT',
        'SERVER_NAME',
        'SERVER_ADDR',
        'SERVER_PORT',
        'LD_PRELOAD',
        'LD_LIBRARY_PATH',
        'PHP_INI_SCAN_DIR',
        'OPENSSL_CONF',
    ];

    /**
     * Load key=value pairs from a .env file into $_ENV and $_SERVER.
     *
     * @return array<string, string> Loaded variables
     */
    public static function load(string $filePath, bool $overwrite = false, bool $populatePutenv = false): array
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

            $upperKey = strtoupper($key);
            if (
                in_array($upperKey, self::FORBIDDEN_KEYS, true)
                || str_starts_with($upperKey, 'HTTP_')
                || str_starts_with($upperKey, 'DYLD_')
            ) {
                continue;
            }

            $rawValue = trim(substr($trimmed, $pos + 1));
            $value = str_replace("\0", '', self::parseValue($rawValue));

            if (!$overwrite && (array_key_exists($key, $_ENV) || array_key_exists($key, $_SERVER) || false !== getenv($key))) {
                continue;
            }

            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
            if ($populatePutenv) {
                putenv($key . '=' . $value);
            }
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
