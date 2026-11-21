<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Closure;
use JsonException;
use Kongono\Core\CoreException;

/** Contained, atomic JSON file cache (zero PHP unserialize() risk). */
final readonly class FileCache implements CacheInterface
{
    private string $dir;

    public function __construct(string $directory)
    {
        if (!is_dir($directory) && !@mkdir($directory, 0o775, true) && !is_dir($directory)) {
            throw new CoreException(sprintf('Unable to create cache directory "%s".', $directory));
        }
        $resolved = realpath($directory);
        if (false === $resolved || !is_dir($resolved)) {
            throw new CoreException(sprintf('Unable to resolve cache directory "%s".', $directory));
        }
        $this->dir = $resolved;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $file = $this->path($key);
        if (!is_file($file)) {
            return $default;
        }
        $raw = @file_get_contents($file);
        if (false === $raw) {
            return $default;
        }
        try {
            $decoded = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            @unlink($file);

            return $default;
        }
        if (!is_array($decoded) || !is_int($decoded['expires_at'] ?? null) || !array_key_exists('value', $decoded)) {
            @unlink($file);

            return $default;
        }
        if ($decoded['expires_at'] <= time()) {
            @unlink($file);

            return $default;
        }

        return $decoded['value'];
    }

    public function set(string $key, mixed $value, int $ttlSeconds = 300): void
    {
        $payload = json_encode([
            'expires_at' => time() + max(1, $ttlSeconds),
            'value' => $value,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $file = $this->path($key);
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (false === file_put_contents($tmp, $payload, LOCK_EX)) {
            throw new CoreException('Failed to write cache entry.');
        }
        if (!@rename($tmp, $file)) {
            @unlink($file);
            if (!@rename($tmp, $file)) {
                @unlink($tmp);
                throw new CoreException('Failed to publish cache entry.');
            }
        }
    }

    public function has(string $key): bool
    {
        $sentinel = new \stdClass();

        return $sentinel !== $this->get($key, $sentinel);
    }

    public function delete(string $key): void
    {
        $file = $this->path($key);
        if (is_file($file)) {
            @unlink($file);
        }
    }

    public function clear(): void
    {
        $files = glob($this->dir . DIRECTORY_SEPARATOR . '*.cache.json');
        if (false === $files) {
            return;
        }
        foreach ($files as $file) {
            @unlink($file);
        }
    }

    public function remember(string $key, int $ttlSeconds, Closure $compute): mixed
    {
        $sentinel = new \stdClass();
        $existing = $this->get($key, $sentinel);
        if ($sentinel !== $existing) {
            return $existing;
        }
        $value = $compute();
        $this->set($key, $value, $ttlSeconds);

        return $value;
    }

    private function path(string $key): string
    {
        return $this->dir . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.cache.json';
    }
}
