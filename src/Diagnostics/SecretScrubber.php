<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

use Stringable;
use Throwable;

/** Scrubs common credential, API key, URI/DSN password, PEM key, JWT, cookie, and JSON/quoted secret patterns before logging or AI transmission. */
final class SecretScrubber
{
    /** @var list<array{0: string, 1: string}> */
    private const array RULES = [
        // PEM private keys (complete OR truncated e.g. via substr()) using non-backtracking unrolled pattern
        ['/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^-]*+(?:-(?!----END [A-Z0-9 ]*PRIVATE KEY-----)[^-]*+)*+(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)/', '[REDACTED_PRIVATE_KEY]'],
        // Database, cache, queue, mail, FTP, LDAP, WS, and HTTP URI credentials (handles @ inside passwords)
        ['/(postgres(?:ql)?|pgsql|mysql|mariadb|redis|rediss|amqp|amqps|mongodb(?:\+srv)?|https?|smtps?|ftps?|sftp|ldaps?|wss?):\/\/[^\s:@\/"\']*+:[^\s\/"\']+@/i', '$1://[REDACTED]@'],
        // Provider API keys, Stripe live/test/restricted keys, Resend, GitHub tokens, Slack tokens, webhook secrets, AWS keys, S3 presigned sigs
        ['/sk-ant-[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/sk-(?:proj-|live_|test_)?[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/', '[REDACTED]'],
        ['/AIza[0-9A-Za-z_-]{20,}/', '[REDACTED]'],
        ['/\bgsk_[A-Za-z0-9_-]{20,}\b/', '[REDACTED]'],
        ['/\bre_[A-Za-z0-9_]{16,}\b/', '[REDACTED]'],
        ['/\bgh[pousr]_[A-Za-z0-9]{20,}\b/', '[REDACTED]'],
        ['/github_pat_[A-Za-z0-9_]{20,}/', '[REDACTED]'],
        ['/\bkgn_pat_[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b/', '[REDACTED]'],
        ['/whsec_[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/', '[REDACTED]'],
        ['/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/', '[REDACTED]'],
        ['/(X-Amz-Signature=)[^&\s"\']+/i', '$1[REDACTED]'],
        ['/(X-Amz-Security-Token=)[^&\s"\']+/i', '$1[REDACTED]'],
        // Authorization headers (Bearer including ':', '%', '=', Basic, Digest, AWS4-HMAC-SHA256) and Cookie / Set-Cookie header lines
        ['/Bearer\s+[A-Za-z0-9._~+:\/%-]+={0,3}/i', 'Bearer [REDACTED]'],
        ['/Basic\s+[A-Za-z0-9+\/_-]+={0,3}/i', 'Basic [REDACTED]'],
        ['/(Authorization\s*:\s*(?:Digest|AWS4-HMAC-SHA256)\s+)[^\r\n]+/i', '$1[REDACTED]'],
        ['/\b((?:set-)?cookie\s*:\s*)[^\r\n]+/i', '$1[REDACTED]'],
        ['/\b(kongono_(?:session|remember)=)[^;\s"\']+/i', '$1[REDACTED]'],
        ['/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/', '[REDACTED_JWT]'],
    ];

    /** @var list<string> */
    private const array SENSITIVE_KEYS = [
        'password',
        'passwd',
        'passphrase',
        'password_hash',
        'password_confirmation',
        'secret',
        'secret_key',
        'secret_access_key',
        'api_key',
        'apikey',
        'app_key',
        'token',
        'jwt',
        'access_token',
        'refresh_token',
        'csrf_token',
        'xsrf_token',
        'session_token',
        'auth_token',
        '_csrf',
        'authorization',
        'proxy_authorization',
        'private_key',
        'private_key_pem',
        'client_secret',
        'webhook_secret',
        'cookie',
        'set_cookie',
        'session_id',
        'signing_key',
        'credential',
        'credentials',
        'x_amz_signature',
        'x_amz_security_token',
        'x_goog_api_key',
        'x_kongono_key',
        'stripe_signature',
        'php_auth_pw',
        'credit_card',
        'card_number',
        'cvv',
        'cvc',
        'ssn',
        'otp',
        'totp',
        'recovery_code',
    ];

    /** @var list<string> */
    private const array SENSITIVE_KEY_PREFIXES = [
        'password_',
        'passwd_',
        'passphrase_',
        'secret_',
        'token_',
        'cookie_',
        'private_key_',
        'api_key_',
        'apikey_',
        'session_id_',
        'credential_',
        'credit_card_',
        'card_number_',
    ];

    public static function scrub(string $text): string
    {
        $result = $text;
        foreach (self::RULES as [$pattern, $replacement]) {
            $replaced = preg_replace($pattern, $replacement, $result);
            if (!is_string($replaced)) {
                // Fail closed if PCRE hits backtrack/JIT limits so secrets can NEVER leak unscrubbed
                return '[REDACTED: SCRUB_FAILED]';
            }
            $result = $replaced;
        }

        return self::scrubSensitiveAssignments($result);
    }

    /**
     * Linear-time key-value assignment scrubber using `isSensitiveKey()` so arbitrarily long keys
     * (>48 chars, camelCase, snake_case, kebab-case) are redacted consistently without PCRE backtracking.
     */
    private static function scrubSensitiveAssignments(string $text): string
    {
        $patterns = [
            // Double-quoted values (`"key": "val"`, `key="val"`, `'key' => "val"`)
            [
                '/(["\']?)([A-Za-z_][A-Za-z0-9_.-]{1,255}+)\1(\s*(?:=>|[:=])\s*)"(?!\[REDACTED)(?!Bearer\s+\[REDACTED)(?!Basic\s+\[REDACTED)(?:\\\\.|[^"\\\\\r\n])*+"/i',
                '"[REDACTED]"',
                false,
            ],
            // Single-quoted values (`'key' => 'val'`, `key='val'`)
            [
                '/(["\']?)([A-Za-z_][A-Za-z0-9_.-]{1,255}+)\1(\s*(?:=>|[:=])\s*)\'(?!\[REDACTED)(?!Bearer\s+\[REDACTED)(?!Basic\s+\[REDACTED)(?:\\\\.|[^\'\\\\\r\n])*+\'/i',
                "'[REDACTED]'",
                false,
            ],
            // Unquoted values (`KEY=val`, `key: val`, `key => val`) — never clobber JSON/PHP `{`, `[`, `null`, `true`, `false`
            [
                '/(["\']?)([A-Za-z_][A-Za-z0-9_.-]{1,255}+)\1(\s*(?:=>|[:=])\s*)(?!\[REDACTED)(?!(?:Bearer|Basic|Digest|AWS4-HMAC-SHA256)\s+\[REDACTED)([^\s,;\]\[\{\}"\']+)/i',
                '[REDACTED]',
                true,
            ],
        ];

        $result = $text;
        foreach ($patterns as [$pattern, $redactedVal, $isUnquoted]) {
            $replaced = preg_replace_callback(
                $pattern,
                static function (array $m) use ($redactedVal, $isUnquoted): string {
                    if (!self::isSensitiveKey($m[2])) {
                        return $m[0];
                    }
                    if ($isUnquoted) {
                        $rawVal = strtolower($m[4] ?? '');
                        if (in_array($rawVal, ['null', 'true', 'false'], true)) {
                            return $m[0];
                        }
                        // Preserve valid JSON syntax when redacting unquoted scalar values under double-quoted JSON keys
                        if ('"' === $m[1] && str_contains($m[3], ':')) {
                            return $m[1] . $m[2] . $m[1] . $m[3] . '"[REDACTED]"';
                        }
                    }

                    return $m[1] . $m[2] . $m[1] . $m[3] . $redactedVal;
                },
                $result,
            );
            if (!is_string($replaced)) {
                return '[REDACTED: SCRUB_FAILED]';
            }
            $result = $replaced;
        }

        return $result;
    }

    /**
     * Recursively scrub structured arrays (logs, diagnostics, API/MCP payloads, AI context).
     *
     * @param array<array-key, mixed> $data
     * @return array<array-key, mixed>
     */
    public static function scrubArray(array $data, int $depth = 0): array
    {
        if ($depth >= 16) {
            return ['_truncated' => '[MAX_DEPTH]'];
        }

        $out = [];
        foreach ($data as $key => $value) {
            $safeKey = is_string($key) ? self::scrub($key) : $key;
            if (is_string($key) && self::isSensitiveKey($key)) {
                $out[$safeKey] = '[REDACTED]';
                continue;
            }

            if (is_string($value)) {
                $out[$safeKey] = self::scrub($value);
            } elseif (is_array($value)) {
                $out[$safeKey] = self::scrubArray($value, $depth + 1);
            } elseif ($value instanceof Throwable) {
                $out[$safeKey] = sprintf('[%s] %s', $value::class, self::scrub($value->getMessage()));
            } elseif ($value instanceof Stringable) {
                $out[$safeKey] = self::scrub((string) $value);
            } elseif (is_object($value)) {
                // Never pass un-scrubbed arbitrary objects (which json_encode may serialize with secret properties)
                $out[$safeKey] = sprintf('[object %s]', $value::class);
            } else {
                $out[$safeKey] = $value;
            }
        }

        return $out;
    }

    public static function isSensitiveKey(string $key): bool
    {
        // Normalize camelCase, acronyms (DBPassword, APISecret, JWTToken, SSHPrivateKey), and kebab-case into snake_case
        $snake = (string) preg_replace('/([A-Z]+)([A-Z][a-z])/', '$1_$2', trim($key));
        $snake = (string) preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', $snake);
        $normalized = strtolower(str_replace(['-', '.', ' '], '_', $snake));

        foreach (self::SENSITIVE_KEYS as $needle) {
            if (
                $normalized === $needle
                || str_ends_with($normalized, '_' . $needle)
                || str_contains($normalized, '_' . $needle . '_')
            ) {
                return true;
            }
        }
        foreach (self::SENSITIVE_KEY_PREFIXES as $prefix) {
            if (str_starts_with($normalized, $prefix)) {
                return true;
            }
        }

        return false;
    }
}
