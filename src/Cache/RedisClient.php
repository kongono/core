<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Kongono\Core\CoreException;
use SensitiveParameter;

/**
 * Zero-dependency pure PHP 8.5 Redis / Valkey RESP2 & RESP3 client over TCP/TLS sockets.
 *
 * Supports `redis://` and `rediss://` URLs, password/ACL authentication, database selection,
 * and deterministic stream injection (`fromStream()`) for offline protocol testing.
 */
final class RedisClient
{
    /** @var resource|null */
    private mixed $stream;

    /** @param resource $stream */
    private function __construct(mixed $stream)
    {
        $this->stream = $stream;
    }

    public static function connect(
        string $host = '127.0.0.1',
        int $port = 6379,
        #[SensitiveParameter]
        ?string $password = null,
        int $database = 0,
        bool $tls = false,
        float $timeout = 3.0,
        ?string $username = null,
    ): self {
        $scheme = $tls ? 'tls' : 'tcp';
        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client(sprintf('%s://%s:%d', $scheme, $host, $port), $errno, $errstr, $timeout);
        if (!is_resource($stream)) {
            throw new CoreException(sprintf('Unable to connect to Redis at %s:%d (%s).', $host, $port, $errstr));
        }

        stream_set_timeout($stream, (int) $timeout, (int) (($timeout - floor($timeout)) * 1_000_000));
        $client = new self($stream);

        if (null !== $password && '' !== $password) {
            if (null !== $username && '' !== $username) {
                $client->command('AUTH', $username, $password);
            } else {
                $client->command('AUTH', $password);
            }
        }
        if ($database > 0) {
            $client->command('SELECT', (string) $database);
        }

        return $client;
    }

    public static function fromUrl(#[SensitiveParameter] string $url, float $timeout = 3.0): self
    {
        $parts = parse_url($url);
        if (false === $parts || !isset($parts['scheme'])) {
            throw new CoreException('Invalid REDIS_URL format.');
        }
        $scheme = strtolower($parts['scheme']);
        if ('redis' !== $scheme && 'rediss' !== $scheme) {
            throw new CoreException(sprintf('Unsupported Redis URL scheme "%s".', $scheme));
        }

        $host = $parts['host'] ?? '127.0.0.1';
        $port = $parts['port'] ?? 6379;
        $user = isset($parts['user']) && '' !== $parts['user'] ? rawurldecode($parts['user']) : null;
        $pass = isset($parts['pass']) ? rawurldecode($parts['pass']) : null;
        $path = trim($parts['path'] ?? '', '/');
        $db = '' !== $path && ctype_digit($path) ? (int) $path : 0;

        return self::connect($host, $port, $pass, $db, 'rediss' === $scheme, $timeout, $user);
    }

    /**
     * Wrap an existing stream resource (e.g. `stream_socket_pair` in unit tests).
     *
     * @param resource $stream
     */
    public static function fromStream(mixed $stream): self
    {
        if (!is_resource($stream)) {
            throw new CoreException('RedisClient::fromStream() requires a valid stream resource.');
        }

        return new self($stream);
    }

    /** Encode one Redis command as a RESP array of bulk strings. */
    public static function encodeCommand(string ...$args): string
    {
        $out = '*' . count($args) . "\r\n";
        foreach ($args as $arg) {
            $out .= '$' . strlen($arg) . "\r\n" . $arg . "\r\n";
        }

        return $out;
    }

    public function command(string ...$args): mixed
    {
        if (!is_resource($this->stream)) {
            throw new CoreException('Redis connection is closed.');
        }

        $wire = self::encodeCommand(...$args);
        $total = strlen($wire);
        $written = 0;
        while ($written < $total) {
            $n = fwrite($this->stream, substr($wire, $written));
            if (false === $n || 0 === $n) {
                throw new CoreException('Failed writing command to Redis stream.');
            }
            $written += $n;
        }

        return $this->readReply();
    }

    public function ping(): string
    {
        $reply = $this->command('PING');

        return is_string($reply) ? $reply : 'PONG';
    }

    public function get(string $key): ?string
    {
        $reply = $this->command('GET', $key);

        return is_string($reply) ? $reply : null;
    }

    public function set(string $key, string $value, ?int $ttlSeconds = null): void
    {
        if (null !== $ttlSeconds && $ttlSeconds > 0) {
            $this->command('SET', $key, $value, 'EX', (string) $ttlSeconds);
        } else {
            $this->command('SET', $key, $value);
        }
    }

    public function del(string ...$keys): int
    {
        if ([] === $keys) {
            return 0;
        }
        $reply = $this->command('DEL', ...$keys);

        return is_int($reply) ? $reply : 0;
    }

    public function exists(string $key): bool
    {
        return 1 === $this->command('EXISTS', $key);
    }

    public function incr(string $key): int
    {
        $reply = $this->command('INCR', $key);

        return is_int($reply) ? $reply : 0;
    }

    public function expire(string $key, int $ttlSeconds): bool
    {
        return 1 === $this->command('EXPIRE', $key, (string) max(1, $ttlSeconds));
    }

    /** @return list<string> */
    public function keys(string $pattern): array
    {
        $reply = $this->command('KEYS', $pattern);
        if (!is_array($reply)) {
            return [];
        }

        $result = [];
        foreach ($reply as $item) {
            if (is_string($item)) {
                $result[] = $item;
            }
        }

        return $result;
    }

    public function close(): void
    {
        if (is_resource($this->stream)) {
            fclose($this->stream);
        }
        $this->stream = null;
    }

    private function readReply(): mixed
    {
        if (!is_resource($this->stream)) {
            throw new CoreException('Redis connection is closed.');
        }

        $line = fgets($this->stream);
        if (false === $line || '' === $line) {
            throw new CoreException('Unexpected EOF while reading Redis reply.');
        }

        $prefix = $line[0];
        $payload = rtrim(substr($line, 1), "\r\n");

        return match ($prefix) {
            '+' => $payload,
            '-' => throw new CoreException('Redis error: ' . $payload),
            ':' => (int) $payload,
            '_' => null,
            '#' => 't' === $payload,
            ',' => (float) $payload,
            '$' => $this->readBulkString((int) $payload),
            '*' => $this->readArray((int) $payload),
            default => throw new CoreException(sprintf('Unsupported Redis RESP prefix "%s".', $prefix)),
        };
    }

    private function readBulkString(int $length): ?string
    {
        if ($length < 0) {
            return null;
        }
        if (!is_resource($this->stream)) {
            throw new CoreException('Redis connection is closed.');
        }

        $remaining = $length + 2; // payload + trailing CRLF
        $buf = '';
        while ($remaining > 0) {
            $chunk = fread($this->stream, $remaining);
            if (false === $chunk || '' === $chunk) {
                throw new CoreException('Unexpected EOF while reading Redis bulk string.');
            }
            $buf .= $chunk;
            $remaining -= strlen($chunk);
        }

        return substr($buf, 0, $length);
    }

    /** @return list<mixed>|null */
    private function readArray(int $count): ?array
    {
        if ($count < 0) {
            return null;
        }
        $items = [];
        for ($i = 0; $i < $count; ++$i) {
            $items[] = $this->readReply();
        }

        return $items;
    }
}
