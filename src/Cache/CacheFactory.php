<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Kongono\Core\Config;

/**
 * Zero-boilerplate horizontal-scaling cache factory:
 * automatically returns `RedisCache` when `REDIS_URL` is set, falling back to `FileCache` for single-node/local setups.
 */
final readonly class CacheFactory
{
    public static function fromEnv(
        string $fallbackDirectory,
        string $prefix = 'kongono:cache:',
        ?string $redisUrlOverride = null,
    ): CacheInterface {
        $url = $redisUrlOverride ?? Config::env('REDIS_URL');
        if (null !== $url && '' !== trim($url)) {
            return new RedisCache(RedisClient::fromUrl($url), prefix: $prefix);
        }

        return new FileCache($fallbackDirectory);
    }
}
