<?php

declare(strict_types=1);

namespace Kongono\Core\Id;

use Kongono\Core\CoreException;

/**
 * Pure PHP 8.5 RFC 9562 UUID generator and validator (`UUIDv7` time-ordered + `UUIDv4` random).
 *
 * `Uuid::v7()` produces B-tree index-friendly, lexicographically time-sortable 128-bit identifiers
 * ideal for PostgreSQL primary keys and multi-tenant records with zero external packages.
 */
final readonly class Uuid
{
    private const string CANONICAL_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i';

    /**
     * Generate an RFC 9562 time-ordered UUIDv7 (48-bit Unix ms timestamp + 74 bits CSPRNG entropy).
     */
    public static function v7(?int $timestampMs = null): string
    {
        $ms = $timestampMs ?? (int) floor(microtime(true) * 1000.0);
        if ($ms < 0 || $ms > 0xFFFF_FFFF_FFFF) {
            throw new CoreException('UUIDv7 timestamp must be a non-negative 48-bit millisecond integer.');
        }

        $rand = random_bytes(10);

        // 48-bit big-endian Unix milliseconds (bytes 0..5)
        $bytes = pack('Nn', ($ms >> 16) & 0xFFFF_FFFF, $ms & 0xFFFF) . $rand;

        // Version 7 in high nibble of byte 6 (0111xxxx)
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x70);
        // RFC 9562 variant 10xxxxxx in byte 8
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        return self::formatBytes($bytes);
    }

    /** Generate a cryptographically random RFC 9562 UUIDv4 (122 bits CSPRNG entropy). */
    public static function v4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        return self::formatBytes($bytes);
    }

    /** Return true when `$value` is a canonical hyphenated RFC 9562 UUID string. */
    public static function isValid(string $value): bool
    {
        return 1 === preg_match(self::CANONICAL_PATTERN, $value);
    }

    /** Extract the RFC 9562 version number (1..8) from a valid UUID string, or null if invalid. */
    public static function version(string $value): ?int
    {
        if (!self::isValid($value)) {
            return null;
        }

        return (int) hexdec($value[14]);
    }

    /**
     * Extract the 48-bit Unix millisecond timestamp embedded in a UUIDv7, or null if not a valid UUIDv7.
     */
    public static function extractTimestampMs(string $uuidV7): ?int
    {
        if (7 !== self::version($uuidV7)) {
            return null;
        }

        $hex = strtolower(substr($uuidV7, 0, 8) . substr($uuidV7, 9, 4));
        $high = (int) hexdec(substr($hex, 0, 8));
        $low = (int) hexdec(substr($hex, 8, 4));

        return ($high << 16) | $low;
    }

    private static function formatBytes(string $bytes): string
    {
        $hex = bin2hex($bytes);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12),
        );
    }
}
