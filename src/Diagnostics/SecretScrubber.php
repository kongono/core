<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/** Scrubs common credential, API key, URI/DSN password, and token patterns before logging or AI transmission. */
final class SecretScrubber
{
    /** @var list<array{0: string, 1: string}> */
    private const array RULES = [
        // Database, cache, queue, and HTTP URI credentials (e.g. postgres://user:pass@host, redis://:pass@host)
        ['/(postgres(?:ql)?|pgsql|mysql|mariadb|redis|rediss|amqp|amqps|mongodb(?:\+srv)?|https?):\/\/[^\s:@\/"\']*:[^\s@\/"\']+@/i', '$1://[REDACTED]@'],
        // Provider API keys, PATs, webhook signing secrets, and AWS access key IDs
        ['/sk-ant-[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/sk-[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/AIza[0-9A-Za-z_-]{20,}/', '[REDACTED]'],
        ['/ghp_[A-Za-z0-9]{20,}/', '[REDACTED]'],
        ['/github_pat_[A-Za-z0-9_]{20,}/', '[REDACTED]'],
        ['/whsec_[A-Za-z0-9_-]{16,}/', '[REDACTED]'],
        ['/\bAKIA[0-9A-Z]{16}\b/', '[REDACTED]'],
        // Authorization headers and generic key=value secret assignments
        ['/Bearer\s+[A-Za-z0-9._~+\/-]+=*/i', '[REDACTED]'],
        ['/(password|passwd|secret|api_key|apikey|token|authorization)\s*[:=]\s*[^\s,;\]"\']+/i', '[REDACTED]'],
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
}
