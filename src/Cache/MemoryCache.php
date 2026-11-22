<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Closure;

/** Bounded process-local cache with explicit TTL expiration, deterministic eviction, and atomic operations. */
final class MemoryCache implements AtomicCacheInterface
{
    /** @var array<string, array{value: mixed, expires_at: int}> */
    private array $entries = [];

    public function __construct(
        private readonly int $maxEntries = 1000,
    ) {}

    public function get(string $key, mixed $default = null, ?int $now = null): mixed
    {
        $ts = $now ?? time();
        if (!isset($this->entries[$key])) {
            return $default;
        }
        if ($this->entries[$key]['expires_at'] <= $ts) {
            unset($this->entries[$key]);

            return $default;
        }

        return $this->entries[$key]['value'];
    }

    public function set(string $key, mixed $value, int $ttlSeconds = 300, ?int $now = null): void
    {
        $ts = $now ?? time();
        if (!isset($this->entries[$key]) && count($this->entries) >= $this->maxEntries) {
            $this->evictExpired($ts);
            if (count($this->entries) >= $this->maxEntries) {
                $oldestKey = array_key_first($this->entries);
                if (null !== $oldestKey) {
                    unset($this->entries[$oldestKey]);
                }
            }
        }
        $this->entries[$key] = [
            'value' => $value,
            'expires_at' => $ts + max(1, $ttlSeconds),
        ];
    }

    public function add(string $key, mixed $value, int $ttlSeconds = 300, ?int $now = null): bool
    {
        $ts = $now ?? time();
        if ($this->has($key, $ts)) {
            return false;
        }
        $this->set($key, $value, $ttlSeconds, $ts);

        return true;
    }

    public function increment(string $key, int $delta = 1, int $ttlSeconds = 300, ?int $now = null): int
    {
        $ts = $now ?? time();
        if (isset($this->entries[$key]) && $this->entries[$key]['expires_at'] > $ts) {
            $current = is_int($this->entries[$key]['value']) ? $this->entries[$key]['value'] : 0;
            $next = $current + $delta;
            $this->entries[$key]['value'] = $next;

            return $next;
        }

        $this->set($key, $delta, $ttlSeconds, $ts);

        return $delta;
    }

    public function pull(string $key, mixed $default = null, ?int $now = null): mixed
    {
        $ts = $now ?? time();
        if (!isset($this->entries[$key])) {
            return $default;
        }
        $entry = $this->entries[$key];
        unset($this->entries[$key]);
        if ($entry['expires_at'] <= $ts) {
            return $default;
        }

        return $entry['value'];
    }

    private function evictExpired(int $now): void
    {
        foreach ($this->entries as $k => $entry) {
            if ($entry['expires_at'] <= $now) {
                unset($this->entries[$k]);
            }
        }
    }

    public function has(string $key, ?int $now = null): bool
    {
        $ts = $now ?? time();
        if (!isset($this->entries[$key])) {
            return false;
        }
        if ($this->entries[$key]['expires_at'] <= $ts) {
            unset($this->entries[$key]);

            return false;
        }

        return true;
    }

    public function delete(string $key): void
    {
        unset($this->entries[$key]);
    }

    public function clear(): void
    {
        $this->entries = [];
    }

    public function remember(string $key, int $ttlSeconds, Closure $compute): mixed
    {
        if ($this->has($key)) {
            /** @var mixed $hit */
            $hit = $this->get($key);

            return $hit;
        }
        $value = $compute();
        $this->set($key, $value, $ttlSeconds);

        return $value;
    }
}
