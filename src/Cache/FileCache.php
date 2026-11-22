<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Closure;
use JsonException;
use Kongono\Core\CoreException;

/** Contained, atomic JSON file cache with owner-only permissions and flock-serialized atomic ops (zero PHP unserialize() risk). */
final readonly class FileCache implements AtomicCacheInterface
{
    private string $dir;

    public function __construct(string $directory)
    {
        if (is_link($directory)) {
            throw new CoreException(sprintf('Cache directory "%s" cannot be a symbolic link.', $directory));
        }
        if (!is_dir($directory) && !@mkdir($directory, 0o700, true) && !is_dir($directory)) {
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
        $entry = $this->readEntry($file);

        return null === $entry ? $default : $entry['value'];
    }

    public function set(string $key, mixed $value, int $ttlSeconds = 300): void
    {
        $this->writeEntry($this->path($key), $value, time() + max(1, $ttlSeconds));
    }

    public function add(string $key, mixed $value, int $ttlSeconds = 300): bool
    {
        return $this->withLock($key, function (string $file) use ($value, $ttlSeconds): bool {
            if (null !== $this->readEntry($file)) {
                return false;
            }
            $this->writeEntry($file, $value, time() + max(1, $ttlSeconds));

            return true;
        });
    }

    public function increment(string $key, int $delta = 1, int $ttlSeconds = 300): int
    {
        return $this->withLock($key, function (string $file) use ($delta, $ttlSeconds): int {
            $entry = $this->readEntry($file);
            if (null !== $entry) {
                $current = is_int($entry['value']) ? $entry['value'] : 0;
                $next = $current + $delta;
                $this->writeEntry($file, $next, $entry['expires_at']);

                return $next;
            }

            $this->writeEntry($file, $delta, time() + max(1, $ttlSeconds));

            return $delta;
        });
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        return $this->withLock($key, function (string $file) use ($default): mixed {
            $entry = $this->readEntry($file);
            if (!is_link($file) && is_file($file)) {
                @unlink($file);
            }

            return null === $entry ? $default : $entry['value'];
        });
    }

    public function has(string $key): bool
    {
        $sentinel = new \stdClass();

        return $sentinel !== $this->get($key, $sentinel);
    }

    public function delete(string $key): void
    {
        $file = $this->path($key);
        if (!is_link($file) && is_file($file)) {
            @unlink($file);
        }
    }

    public function clear(): void
    {
        foreach (['*.cache.json', '*.cache.json.lock'] as $pattern) {
            $files = glob($this->dir . DIRECTORY_SEPARATOR . $pattern);
            if (false === $files) {
                continue;
            }
            foreach ($files as $file) {
                if (!is_link($file) && is_file($file)) {
                    @unlink($file);
                }
            }
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

    /** @return array{expires_at: int, value: mixed}|null */
    private function readEntry(string $file): ?array
    {
        if (is_link($file) || !is_file($file)) {
            return null;
        }
        $raw = @file_get_contents($file);
        if (false === $raw) {
            return null;
        }
        try {
            $decoded = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            @unlink($file);

            return null;
        }
        if (!is_array($decoded) || !is_int($decoded['expires_at'] ?? null) || !array_key_exists('value', $decoded)) {
            @unlink($file);

            return null;
        }
        if ($decoded['expires_at'] <= time()) {
            @unlink($file);

            return null;
        }

        return [
            'expires_at' => $decoded['expires_at'],
            'value' => $decoded['value'],
        ];
    }

    private function writeEntry(string $file, mixed $value, int $expiresAt): void
    {
        if (is_link($file)) {
            throw new CoreException('Refusing to overwrite symbolic link cache entry.');
        }

        $payload = json_encode([
            'expires_at' => $expiresAt,
            'value' => $value,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $tmp = $file . '.' . bin2hex(random_bytes(16)) . '.tmp';
        $handle = @fopen($tmp, 'xb');
        if (false === $handle) {
            throw new CoreException('Failed to create temporary cache entry.');
        }

        try {
            @chmod($tmp, 0o600);
            $written = fwrite($handle, $payload);
            if (false === $written || $written !== strlen($payload)) {
                throw new CoreException('Failed to write cache entry.');
            }
        } finally {
            fclose($handle);
        }

        if (!@rename($tmp, $file)) {
            @unlink($file);
            if (!@rename($tmp, $file)) {
                @unlink($tmp);
                throw new CoreException('Failed to publish cache entry.');
            }
        }
    }

    /**
     * @template T
     * @param Closure(string): T $fn
     * @return T
     */
    private function withLock(string $key, Closure $fn): mixed
    {
        $file = $this->path($key);
        $lockFile = $file . '.lock';
        if (is_link($lockFile)) {
            throw new CoreException('Refusing to open symbolic link cache lock.');
        }

        $handle = @fopen($lockFile, 'c+b');
        if (false === $handle) {
            throw new CoreException('Unable to acquire cache lock file.');
        }
        @chmod($lockFile, 0o600);

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new CoreException('Unable to lock cache entry.');
            }

            return $fn($file);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
