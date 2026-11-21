<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/** Scrubs common credential, API key, and token patterns before logging or AI transmission. */
final class SecretScrubber
{
    /** @var list<string> */
    private const array PATTERNS = [
        '/sk-[A-Za-z0-9_-]{16,}/',
        '/sk-ant-[A-Za-z0-9_-]{16,}/',
        '/AIza[0-9A-Za-z_-]{20,}/',
        '/ghp_[A-Za-z0-9]{20,}/',
        '/Bearer\s+[A-Za-z0-9._~+\/-]+=*/i',
        '/(password|passwd|secret|api_key|apikey|token|authorization)\s*[:=]\s*[^\s,;\]"\']+/i',
    ];

    public static function scrub(string $text): string
    {
        $result = $text;
        foreach (self::PATTERNS as $pattern) {
            $replaced = preg_replace($pattern, '[REDACTED]', $result);
            if (is_string($replaced)) {
                $result = $replaced;
            }
        }

        return $result;
    }
}
