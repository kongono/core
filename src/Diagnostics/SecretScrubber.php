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
        ['/\bre_[A-Za-z0-9_]{16,}\b/', '[REDACTED]'],
        ['/\bgh[pousr]_[A-Za-z0-9]{20,}\b/', '[REDACTED]'],
        ['/github_pat_[A-Za-z0-9_]{20,}/', '[REDACTED]'],
        ['/\bkgn_pat_[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b/', '[REDACTED]'],
        ['/whsec_[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/', '[REDACTED]'],
        ['/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/', '[REDACTED]'],
        ['/(X-Amz-Signature=)[^&\s"\']+/i', '$1[REDACTED]'],
        // Authorization headers (Bearer including ':', Basic, Digest, AWS4-HMAC-SHA256) and Cookie / Set-Cookie header lines
        ['/Bearer\s+[A-Za-z0-9._~+:\/-]+={0,3}/i', 'Bearer [REDACTED]'],
        ['/Basic\s+[A-Za-z0-9+\/_-]+={0,3}/i', 'Basic [REDACTED]'],
        ['/(Authorization\s*:\s*(?:Digest|AWS4-HMAC-SHA256)\s+)[^\r\n]+/i', '$1[REDACTED]'],
        ['/(^|[\r\n])([ \t]*(?:set-)?cookie\s*:\s*)[^\r\n]+/im', '$1$2[REDACTED]'],
        ['/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/', '[REDACTED_JWT]'],
        // Quoted and JSON key-value secret assignments (bounded key prefix prevents PCRE backtrack limit DoS; consumes escaped quotes)
        ['/(["\']?\b[A-Za-z0-9_-]{0,48}(?:password|passwd|passphrase|secret|secret[_-]?access[_-]?key|secret[_-]?key|api[_-]?key|apikey|app_key|token|authorization|private[_-]?key|signing[_-]?key|credential|cookie|session[_-]?id)["\']?\s*[:=]\s*)"(?!\[REDACTED)(?!Bearer\s+\[REDACTED)(?!Basic\s+\[REDACTED)(?:\\\\.|[^"\\\\\r\n])*+"/i', '$1"[REDACTED]"'],
        ['/(["\']?\b[A-Za-z0-9_-]{0,48}(?:password|passwd|passphrase|secret|secret[_-]?access[_-]?key|secret[_-]?key|api[_-]?key|apikey|app_key|token|authorization|private[_-]?key|signing[_-]?key|credential|cookie|session[_-]?id)["\']?\s*[:=]\s*)\'(?!\[REDACTED)(?!Bearer\s+\[REDACTED)(?!Basic\s+\[REDACTED)(?:\\\\.|[^\'\\\\\r\n])*+\'/i', '$1\'[REDACTED]\''],
        // Generic unquoted key=value / key: value secret assignments (bounded key prefix prevents PCRE backtrack bypass)
        ['/(\b[A-Za-z0-9_-]{0,48}(?:password|passwd|passphrase|secret|secret[_-]?access[_-]?key|secret[_-]?key|api[_-]?key|apikey|app_key|token|authorization|private[_-]?key|signing[_-]?key|cookie|session[_-]?id))(\s*[:=]\s*)(?!\[REDACTED)(?!(?:Bearer|Basic|Digest|AWS4-HMAC-SHA256)\s+\[REDACTED)[^\s,;\]"\'}]+/i', '$1$2[REDACTED]'],
    ];

    /** @var list<string> */
    private const array SENSITIVE_KEYS = [
        'password',
        'passwd',
        'passphrase',
        'password_hash',
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
        'auth_token',
        'authorization',
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
            if (is_string($key) && self::isSensitiveKey($key)) {
                $out[$key] = '[REDACTED]';
                continue;
            }

            if (is_string($value)) {
                $out[$key] = self::scrub($value);
            } elseif (is_array($value)) {
                $out[$key] = self::scrubArray($value, $depth + 1);
            } elseif ($value instanceof Throwable) {
                $out[$key] = sprintf('[%s] %s', $value::class, self::scrub($value->getMessage()));
            } elseif ($value instanceof Stringable) {
                $out[$key] = self::scrub((string) $value);
            } elseif (is_object($value)) {
                // Never pass un-scrubbed arbitrary objects (which json_encode may serialize with secret properties)
                $out[$key] = sprintf('[object %s]', $value::class);
            } else {
                $out[$key] = $value;
            }
        }

        return $out;
    }

    public static function isSensitiveKey(string $key): bool
    {
        // Normalize camelCase and kebab-case into snake_case (e.g. clientSecret -> client_secret, X-API-Key -> x_api_key)
        $snake = (string) preg_replace('/([a-z0-9])([A-Z])/', '$1_$2', trim($key));
        $normalized = strtolower(str_replace('-', '_', $snake));

        foreach (self::SENSITIVE_KEYS as $needle) {
            if ($normalized === $needle || str_ends_with($normalized, '_' . $needle)) {
                return true;
            }
        }

        return false;
    }
}
