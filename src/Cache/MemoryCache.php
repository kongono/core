<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Closure;

/** Bounded process-local cache with explicit TTL expiration and deterministic eviction. */
final class MemoryCache implements CacheInterface
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
            $oldestKey = array_key_first($this->entries);
            if (null !== $oldestKey) {
                unset($this->entries[$oldestKey]);
            }
        }
        $this->entries[$key] = [
            'value' => $value,
            'expires_at' => $ts + max(1, $ttlSeconds),
        ];
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
