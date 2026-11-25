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
        $cleanDir = rtrim($directory, '/\\');
        if ('' !== $cleanDir && is_link($cleanDir)) {
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
        $entry = $this->readEntry($file, unlinkExpired: false);

        return null === $entry ? $default : $entry['value'];
    }

    public function set(string $key, mixed $value, int $ttlSeconds = 300): void
    {
        $this->withLock($key, function (string $file) use ($value, $ttlSeconds): void {
            $this->writeEntry($file, $value, time() + max(1, $ttlSeconds));
        });

        if (1 === random_int(1, 100)) {
            $this->pruneExpired();
        }
    }

    /**
     * Remove expired cache files in bounded batches to prevent unbounded inode accumulation.
     */
    public function pruneExpired(int $maxScan = 200): int
    {
        $files = glob($this->dir . DIRECTORY_SEPARATOR . '*.cache.json');
        if (false === $files) {
            return 0;
        }

        $pruned = 0;
        $scanned = 0;
        $limit = max(1, $maxScan);
        foreach ($files as $file) {
            if ($scanned >= $limit) {
                break;
            }
            ++$scanned;
            if (is_link($file) || !is_file($file)) {
                continue;
            }
            $base = basename($file);
            if (strlen($base) < 2) {
                continue;
            }
            $shard = substr($base, 0, 2);
            if ($this->withShardLock($shard, fn(): bool => $this->unlinkIfExpired($file))) {
                ++$pruned;
            }
        }

        return $pruned;
    }

    private function unlinkIfExpired(string $file): bool
    {
        if (null !== $this->readEntry($file, unlinkExpired: true)) {
            return false;
        }
        clearstatcache(true, $file);

        return !is_file($file);
    }

    public function add(string $key, mixed $value, int $ttlSeconds = 300): bool
    {
        return $this->withLock($key, function (string $file) use ($value, $ttlSeconds): bool {
            if (null !== $this->readEntry($file, unlinkExpired: true)) {
                return false;
            }
            $this->writeEntry($file, $value, time() + max(1, $ttlSeconds));

            return true;
        });
    }

    public function increment(string $key, int $delta = 1, int $ttlSeconds = 300): int
    {
        return $this->withLock($key, function (string $file) use ($delta, $ttlSeconds): int {
            $entry = $this->readEntry($file, unlinkExpired: true);
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
            $entry = $this->readEntry($file, unlinkExpired: true);
            if (!is_link($file) && is_file($file)) {
                @unlink($file);
            }

            return null === $entry ? $default : $entry['value'];
        });
    }

    public function compareAndDelete(string $key, mixed $expectedValue): bool
    {
        return $this->withLock($key, function (string $file) use ($expectedValue): bool {
            $entry = $this->readEntry($file, unlinkExpired: true);
            if (null === $entry || $entry['value'] !== $expectedValue) {
                return false;
            }
            if (!is_link($file) && is_file($file)) {
                @unlink($file);
            }

            return true;
        });
    }

    public function has(string $key): bool
    {
        $sentinel = new \stdClass();

        return $sentinel !== $this->get($key, $sentinel);
    }

    public function delete(string $key): void
    {
        $this->withLock($key, static function (string $file): void {
            if (!is_link($file) && is_file($file)) {
                @unlink($file);
            }
        });
    }

    public function clear(): void
    {
        // Only remove data files — never unlink active striped lock pool files
        $files = glob($this->dir . DIRECTORY_SEPARATOR . '*.cache.json');
        if (false === $files) {
            return;
        }
        foreach ($files as $file) {
            if (!is_link($file) && is_file($file)) {
                @unlink($file);
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
    private function readEntry(string $file, bool $unlinkExpired): ?array
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
            if ($unlinkExpired) {
                @unlink($file);
            }

            return null;
        }
        if (!is_array($decoded) || !is_int($decoded['expires_at'] ?? null) || !array_key_exists('value', $decoded)) {
            if ($unlinkExpired) {
                @unlink($file);
            }

            return null;
        }
        if ($decoded['expires_at'] <= time()) {
            if ($unlinkExpired) {
                @unlink($file);
            }

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
            fclose($handle);
        } catch (\Throwable $e) {
            if (is_resource($handle)) {
                fclose($handle);
            }
            @unlink($tmp);
            throw $e;
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
     * Fixed 256-shard flock pool prevents unbounded per-key lock-file inode exhaustion
     * while preserving strict mutual exclusion even across clear().
     *
     * @template T
     * @param Closure(string): T $fn
     * @return T
     */
    private function withLock(string $key, Closure $fn): mixed
    {
        $hash = hash('sha256', $key);
        $file = $this->dir . DIRECTORY_SEPARATOR . $hash . '.cache.json';

        return $this->withShardLock(substr($hash, 0, 2), static fn(): mixed => $fn($file));
    }

    /**
     * @template T
     * @param Closure(): T $fn
     * @return T
     */
    private function withShardLock(string $shard, Closure $fn): mixed
    {
        $safeShard = preg_replace('/[^0-9a-f]/', '0', strtolower($shard));
        $lockFile = $this->dir . DIRECTORY_SEPARATOR . 'shard-' . (is_string($safeShard) && '' !== $safeShard ? $safeShard : '00') . '.lock';
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

            return $fn();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
