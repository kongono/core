<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/**
 * Generates opaque, non-sequential incident reference IDs (e.g. `KGN-20261123-7F3A9C12`).
 *
 * Safe to display to end users in production so support tickets correlate directly to
 * server-side 5W1H logs without exposing server hostnames, PIDs, or request counters.
 */
final readonly class ErrorReference
{
    public static function generate(): string
    {
        return sprintf('KGN-%s-%s', gmdate('Ymd'), strtoupper(bin2hex(random_bytes(4))));
    }
}
