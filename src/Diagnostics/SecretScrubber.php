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
        // PEM private keys (complete OR truncated e.g. via substr())
        ['/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)/', '[REDACTED_PRIVATE_KEY]'],
        // Database, cache, queue, and HTTP URI credentials (e.g. postgres://user:pass@host, redis://:pass@host)
        ['/(postgres(?:ql)?|pgsql|mysql|mariadb|redis|rediss|amqp|amqps|mongodb(?:\+srv)?|https?):\/\/[^\s:@\/"\']*:[^\s@\/"\']+@/i', '$1://[REDACTED]@'],
        // Provider API keys, Stripe live/restricted keys, Resend, GitHub tokens, Slack tokens, webhook signing secrets, AWS access keys
        ['/sk-ant-[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/sk-(?:proj-|live_|test_)?[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/(?:sk|rk)_live_[A-Za-z0-9]{16,}/', '[REDACTED]'],
        ['/AIza[0-9A-Za-z_-]{20,}/', '[REDACTED]'],
        ['/\bre_[A-Za-z0-9_]{16,}\b/', '[REDACTED]'],
        ['/\bgh[pousr]_[A-Za-z0-9]{20,}\b/', '[REDACTED]'],
        ['/github_pat_[A-Za-z0-9_]{20,}/', '[REDACTED]'],
        ['/whsec_[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/', '[REDACTED]'],
        ['/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/', '[REDACTED]'],
        // Authorization headers (Bearer, Basic, Digest, AWS4-HMAC-SHA256) and Cookie / Set-Cookie header lines
        ['/Bearer\s+[A-Za-z0-9._~+\/-]+=*/i', 'Bearer [REDACTED]'],
        ['/Basic\s+[A-Za-z0-9+\/_-]+=*/i', 'Basic [REDACTED]'],
        ['/(Authorization\s*:\s*(?:Digest|AWS4-HMAC-SHA256)\s+)[^\r\n]+/i', '$1[REDACTED]'],
        ['/(^|[\r\n])([ \t]*(?:set-)?cookie\s*:\s*)[^\r\n]+/im', '$1$2[REDACTED]'],
        ['/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/', '[REDACTED_JWT]'],
        // Quoted and JSON key-value secret assignments (e.g. {"password":"..."}, secret='...')
        ['/(["\']?[A-Za-z0-9_-]*(?:password|passwd|secret|api[_-]?key|apikey|app_key|token|authorization|private[_-]?key|signing[_-]?key|credential|cookie)["\']?\s*[:=]\s*)"(?!\[REDACTED)(?!Bearer\s+\[REDACTED)(?!Basic\s+\[REDACTED)[^"\r\n]*"/i', '$1"[REDACTED]"'],
        ['/(["\']?[A-Za-z0-9_-]*(?:password|passwd|secret|api[_-]?key|apikey|app_key|token|authorization|private[_-]?key|signing[_-]?key|credential|cookie)["\']?\s*[:=]\s*)\'(?!\[REDACTED)(?!Bearer\s+\[REDACTED)(?!Basic\s+\[REDACTED)[^\'\r\n]*\'/i', '$1\'[REDACTED]\''],
        // Generic unquoted key=value / key: value secret assignments (preserves key name and skips already-redacted placeholders)
        ['/([A-Za-z0-9_-]*(?:password|passwd|secret|api[_-]?key|apikey|app_key|token|authorization|private[_-]?key|signing[_-]?key|cookie))(\s*[:=]\s*)(?!\[REDACTED)(?!(?:Bearer|Basic|Digest|AWS4-HMAC-SHA256)\s+\[REDACTED)[^\s,;\]"\'}]+/i', '$1$2[REDACTED]'],
    ];

    /** @var list<string> */
    private const array SENSITIVE_KEYS = [
        'password',
        'passwd',
        'secret',
        'api_key',
        'apikey',
        'app_key',
        'token',
        'access_token',
        'refresh_token',
        'csrf_token',
        'auth_token',
        'authorization',
        'private_key',
        'client_secret',
        'webhook_secret',
        'cookie',
        'set_cookie',
        'session_id',
        'signing_key',
        'credential',
        'credentials',
    ];

    public static function scrub(string $text): string
    {
        $result = $text;
        foreach (self::RULES as [$pattern, $replacement]) {
            $replaced = preg_replace($pattern, $replacement, $result);
            if (is_string($replaced)) {
                $result = $replaced;
            }
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
