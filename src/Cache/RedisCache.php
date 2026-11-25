<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Closure;
use JsonException;
use Kongono\Core\CoreException;

/**
 * Distributed Redis / Valkey cache backed by Kongono's zero-dependency `RedisClient`.
 *
 * Works seamlessly with `CacheSessionStore` and `RateLimitMiddleware` for multi-node scaling.
 */
final readonly class RedisCache implements AtomicCacheInterface
{
    public function __construct(
        private RedisClient $redis,
        private string $prefix = 'kongono:cache:',
    ) {
        if ('' === $prefix) {
            throw new CoreException('RedisCache prefix cannot be empty.');
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $raw = $this->redis->get($this->prefixed($key));
        if (null === $raw) {
            return $default;
        }

        try {
            return json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $default;
        }
    }

    public function set(string $key, mixed $value, int $ttlSeconds = 300): void
    {
        $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $this->redis->set($this->prefixed($key), $encoded, max(1, $ttlSeconds));
    }

    public function add(string $key, mixed $value, int $ttlSeconds = 300): bool
    {
        $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return $this->redis->setNx($this->prefixed($key), $encoded, max(1, $ttlSeconds));
    }

    public function increment(string $key, int $delta = 1, int $ttlSeconds = 300): int
    {
        return $this->redis->incrByWithTtl($this->prefixed($key), $delta, max(1, $ttlSeconds));
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        $raw = $this->redis->getDel($this->prefixed($key));
        if (null === $raw) {
            return $default;
        }

        try {
            return json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $default;
        }
    }

    public function has(string $key): bool
    {
        return $this->redis->exists($this->prefixed($key));
    }

    public function delete(string $key): void
    {
        $this->redis->del($this->prefixed($key));
    }

    /** Atomically delete `$key` only when its stored value matches `$expectedValue` (safe distributed lock release). */
    public function compareAndDelete(string $key, mixed $expectedValue): bool
    {
        $expectedJson = json_encode($expectedValue, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $lua = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";
        $reply = $this->redis->eval($lua, [$this->prefixed($key)], [$expectedJson]);

        return 1 === $reply || '1' === $reply;
    }

    public function clear(): void
    {
        // Non-blocking SCAN with glob-escaped prefix prevents Redis event-loop freezes & cross-prefix wildcard deletion
        $escapedPrefix = str_replace(['\\', '*', '?', '[', ']'], ['\\\\', '\\*', '\\?', '\\[', '\\]'], $this->prefix);
        $cursor = '0';
        $iterations = 0;
        do {
            [$cursor, $batch] = $this->redis->scan($cursor, $escapedPrefix . '*', 500);
            if ([] !== $batch) {
                $this->redis->del(...$batch);
            }
            ++$iterations;
        } while ('0' !== $cursor && $iterations < 10_000);
    }

    public function remember(string $key, int $ttlSeconds, Closure $compute): mixed
    {
        $sentinel = new \stdClass();
        $cached = $this->get($key, $sentinel);
        if ($cached !== $sentinel) {
            /** @var mixed $cached */
            return $cached;
        }

        $value = $compute();
        $this->set($key, $value, $ttlSeconds);

        return $value;
    }

    private function prefixed(string $key): string
    {
        return $this->prefix . $key;
    }
}
