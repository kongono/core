<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Closure;
use JsonException;

/**
 * Distributed Redis / Valkey cache backed by Kongono's zero-dependency `RedisClient`.
 *
 * Works seamlessly with `CacheSessionStore` and `RateLimitMiddleware` for multi-node scaling.
 */
final readonly class RedisCache implements CacheInterface
{
    public function __construct(
        private RedisClient $redis,
        private string $prefix = 'kongono:cache:',
    ) {}

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

    public function has(string $key): bool
    {
        return $this->redis->exists($this->prefixed($key));
    }

    public function delete(string $key): void
    {
        $this->redis->del($this->prefixed($key));
    }

    public function clear(): void
    {
        $keys = $this->redis->keys($this->prefix . '*');
        if ([] !== $keys) {
            $this->redis->del(...$keys);
        }
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
