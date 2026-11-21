<?php

declare(strict_types=1);

namespace Kongono\Core\Features;

use Closure;
use Kongono\Core\Cache\CacheInterface;

/**
 * Zero-dependency Feature Flags & deterministic progressive percentage rollouts.
 *
 * Supports code-defined resolvers, consistent-hashed percentage rollouts (zero DB hits),
 * and optional CacheInterface-backed runtime per-scope overrides.
 */
final class FeatureManager
{
    /** @var array<string, Closure(?string): bool> */
    private array $resolvers = [];

    /** @var array<string, bool> */
    private array $memoryOverrides = [];

    public function __construct(
        private readonly ?CacheInterface $cache = null,
        private readonly string $cachePrefix = 'kongono:feature:',
    ) {}

    /** @param Closure(?string): bool $resolver */
    public function define(string $feature, Closure $resolver): self
    {
        $this->resolvers[$feature] = $resolver;

        return $this;
    }

    /** Define a deterministic percentage rollout (0–100) using consistent hashing on the scope key. */
    public function rollout(string $feature, int $percentage): self
    {
        $clamped = max(0, min(100, $percentage));

        return $this->define($feature, static function (?string $scopeKey) use ($feature, $clamped): bool {
            if (0 === $clamped) {
                return false;
            }
            if (100 === $clamped) {
                return true;
            }
            if (null === $scopeKey || '' === $scopeKey) {
                return false;
            }
            $hex = substr(hash('xxh128', $feature . ':' . $scopeKey), 0, 8);
            $bucket = hexdec($hex) % 100;

            return $bucket < $clamped;
        });
    }

    /** Explicitly enable a feature globally (null scope) or for a specific user/tenant scope. */
    public function enable(string $feature, ?string $scopeKey = null, int $ttlSeconds = 86400): self
    {
        return $this->setOverride($feature, $scopeKey, true, $ttlSeconds);
    }

    /** Explicitly disable a feature globally (null scope) or for a specific user/tenant scope. */
    public function disable(string $feature, ?string $scopeKey = null, int $ttlSeconds = 86400): self
    {
        return $this->setOverride($feature, $scopeKey, false, $ttlSeconds);
    }

    /** Evaluate whether a feature flag is active (fails closed to false if undefined). */
    public function active(string $feature, ?string $scopeKey = null): bool
    {
        if (null !== $scopeKey) {
            $scoped = $this->getOverride($feature, $scopeKey);
            if (null !== $scoped) {
                return $scoped;
            }
        }

        $global = $this->getOverride($feature, null);
        if (null !== $global) {
            return $global;
        }

        if (isset($this->resolvers[$feature])) {
            return ($this->resolvers[$feature])($scopeKey);
        }

        return false;
    }

    /**
     * Evaluate all defined feature flags for a scope key (ideal for frontend bootstrapping).
     *
     * @return array<string, bool>
     */
    public function all(?string $scopeKey = null): array
    {
        $out = [];
        foreach (array_keys($this->resolvers) as $feature) {
            $out[$feature] = $this->active($feature, $scopeKey);
        }

        return $out;
    }

    private function setOverride(string $feature, ?string $scopeKey, bool $value, int $ttlSeconds): self
    {
        $key = $this->overrideKey($feature, $scopeKey);
        $this->memoryOverrides[$key] = $value;
        $this->cache?->set($key, $value, $ttlSeconds);

        return $this;
    }

    private function getOverride(string $feature, ?string $scopeKey): ?bool
    {
        $key = $this->overrideKey($feature, $scopeKey);
        if (array_key_exists($key, $this->memoryOverrides)) {
            return $this->memoryOverrides[$key];
        }
        $cached = $this->cache?->get($key);

        return is_bool($cached) ? $cached : null;
    }

    private function overrideKey(string $feature, ?string $scopeKey): string
    {
        return $this->cachePrefix . $feature . ':' . ($scopeKey ?? '__global__');
    }
}
