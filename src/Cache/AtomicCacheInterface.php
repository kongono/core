<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

/**
 * Cache extension providing atomic compare-and-set, increment, and single-use pull primitives
 * so rate limiters, idempotency locks, and single-use auth challenges never race under concurrency.
 */
interface AtomicCacheInterface extends CacheInterface
{
    /** Atomically store a value only if the key does not already exist (or has expired). */
    public function add(string $key, mixed $value, int $ttlSeconds = 300): bool;

    /** Atomically increment an integer counter by $delta, initializing with $ttlSeconds on first write. */
    public function increment(string $key, int $delta = 1, int $ttlSeconds = 300): int;

    /** Atomically read and delete a key so single-use tokens/challenges can be consumed at most once. */
    public function pull(string $key, mixed $default = null): mixed;
}
