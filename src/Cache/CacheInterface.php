<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Closure;

/** Explicit derived-data cache contract (never authoritative truth; JSON-safe values). */
interface CacheInterface
{
    public function get(string $key, mixed $default = null): mixed;

    public function set(string $key, mixed $value, int $ttlSeconds = 300): void;

    public function has(string $key): bool;

    public function delete(string $key): void;

    public function clear(): void;

    /**
     * Fetch a cached value or compute and store it on miss.
     *
     * @template T
     * @param Closure(): T $compute
     * @return T
     */
    public function remember(string $key, int $ttlSeconds, Closure $compute): mixed;
}
