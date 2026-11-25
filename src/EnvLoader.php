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
        'REMOTE_USER',
        'PHP_AUTH_USER',
        'PHP_AUTH_PW',
        'HTTPS',
        'REQUEST_URI',
        'REQUEST_METHOD',
        'REQUEST_SCHEME',
        'QUERY_STRING',
        'CONTENT_TYPE',
        'CONTENT_LENGTH',
        'SCRIPT_FILENAME',
        'SCRIPT_NAME',
        'DOCUMENT_ROOT',
        'SERVER_NAME',
        'SERVER_ADDR',
        'SERVER_PORT',
        'LD_PRELOAD',
        'LD_LIBRARY_PATH',
        'PHP_INI_SCAN_DIR',
        'PHPRC',
        'OPENSSL_CONF',
        'OPENSSL_MODULES',
        'OPENSSL_ENGINES',
        'PATH_INFO',
        'PHP_SELF',
        'HTTPS_PROXY',
        'ALL_PROXY',
        'NO_PROXY',
        'CURL_CA_BUNDLE',
        'SSL_CERT_FILE',
        'SSL_CERT_DIR',
        'PATH',
        'COMSPEC',
        'PATHEXT',
        'BASH_ENV',
        'ENV',
        'IFS',
        'GCONV_PATH',
        'HOSTALIASES',
        'RESOLV_HOST_CONF',
        'NODE_OPTIONS',
        'GIT_SSH_COMMAND',
        'SENDMAIL_PATH',
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
        foreach ($lines as $index => $line) {
            if (0 === $index && str_starts_with($line, "\xEF\xBB\xBF")) {
                $line = substr($line, 3);
            }
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
                || str_starts_with($upperKey, 'LD_')
                || str_starts_with($upperKey, 'DYLD_')
                || str_starts_with($upperKey, 'PHP_INI_')
                || str_starts_with($upperKey, 'ZEND_')
                || str_starts_with($upperKey, 'BASH_FUNC_')
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
        $len = strlen($raw);
        if (0 === $len) {
            return '';
        }

        $first = $raw[0];
        if ('"' === $first || "'" === $first) {
            $out = '';
            $escaped = false;
            for ($i = 1; $i < $len; ++$i) {
                $ch = $raw[$i];
                if ('"' === $first && $escaped) {
                    $out .= match ($ch) {
                        'n' => "\n",
                        'r' => "\r",
                        't' => "\t",
                        '"' => '"',
                        '\\' => '\\',
                        default => '\\' . $ch,
                    };
                    $escaped = false;
                    continue;
                }
                if ('"' === $first && '\\' === $ch) {
                    $escaped = true;
                    continue;
                }
                if ($ch === $first) {
                    // Only accept closing quote if remaining characters are whitespace or a trailing # comment
                    $tail = ltrim(substr($raw, $i + 1));
                    if ('' === $tail || str_starts_with($tail, '#')) {
                        return $out;
                    }
                }
                $out .= $ch;
            }
            if ($escaped) {
                $out .= '\\';
            }

            return $out;
        }

        // Strip inline comments on unquoted values preceded by space or tab
        if (1 === preg_match('/[ \t]#/', $raw, $m, PREG_OFFSET_CAPTURE)) {
            return rtrim(substr($raw, 0, $m[0][1]));
        }

        return $raw;
    }
}
