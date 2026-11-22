<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/** Scrubs common credential, API key, URI/DSN password, PEM key, JWT, and token patterns before logging or AI transmission. */
final class SecretScrubber
{
    /** @var list<array{0: string, 1: string}> */
    private const array RULES = [
        // PEM private keys (RSA/EC/Ed25519/OpenSSH)
        ['/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/', '[REDACTED_PRIVATE_KEY]'],
        // Database, cache, queue, and HTTP URI credentials (e.g. postgres://user:pass@host, redis://:pass@host)
        ['/(postgres(?:ql)?|pgsql|mysql|mariadb|redis|rediss|amqp|amqps|mongodb(?:\+srv)?|https?):\/\/[^\s:@\/"\']*:[^\s@\/"\']+@/i', '$1://[REDACTED]@'],
        // Provider API keys, Stripe live/restricted keys, PATs, webhook signing secrets, and AWS access key IDs
        ['/sk-ant-[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/sk-(?:proj-|live_|test_)?[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/(?:sk|rk)_live_[A-Za-z0-9]{16,}/', '[REDACTED]'],
        ['/AIza[0-9A-Za-z_-]{20,}/', '[REDACTED]'],
        ['/ghp_[A-Za-z0-9]{20,}/', '[REDACTED]'],
        ['/github_pat_[A-Za-z0-9_]{20,}/', '[REDACTED]'],
        ['/whsec_[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/', '[REDACTED]'],
        ['/\bAKIA[0-9A-Z]{16}\b/', '[REDACTED]'],
        // Bearer tokens and compact JWTs
        ['/Bearer\s+[A-Za-z0-9._~+\/-]+=*/i', 'Bearer [REDACTED]'],
        ['/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/', '[REDACTED_JWT]'],
        // Generic key=value / key: value secret assignments (preserves key name and skips already-redacted placeholders)
        ['/(password|passwd|secret|api_key|apikey|token|authorization)(\s*[:=]\s*)(?!\[REDACTED)(?!Bearer\s+\[REDACTED)[^\s,;\]"\']+/i', '$1$2[REDACTED]'],
    ];

    /** @var list<string> */
    private const array SENSITIVE_KEYS = [
        'password',
        'passwd',
        'secret',
        'api_key',
        'apikey',
        'token',
        'access_token',
        'refresh_token',
        'authorization',
        'private_key',
        'client_secret',
        'webhook_secret',
        'cookie',
        'set_cookie',
        'set-cookie',
        'session_id',
        'signing_key',
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
    public static function scrubArray(array $data): array
    {
        $out = [];
        foreach ($data as $key => $value) {
            if (is_string($key) && self::isSensitiveKey($key)) {
                $out[$key] = '[REDACTED]';
                continue;
            }

            if (is_string($value)) {
                $out[$key] = self::scrub($value);
            } elseif (is_array($value)) {
                $out[$key] = self::scrubArray($value);
            } else {
                $out[$key] = $value;
            }
        }

        return $out;
    }

    private static function isSensitiveKey(string $key): bool
    {
        $lower = strtolower(trim($key));
        foreach (self::SENSITIVE_KEYS as $needle) {
            if ($lower === $needle || str_ends_with($lower, '_' . $needle)) {
                return true;
            }
        }

        return false;
    }
}
