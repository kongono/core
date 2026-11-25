<?php

declare(strict_types=1);

namespace Kongono\Core\Cache;

use Closure;
use Kongono\Core\CoreException;
use SensitiveParameter;

/**
 * Zero-dependency pure PHP 8.5 Redis / Valkey RESP2 & RESP3 client over TCP/TLS sockets.
 *
 * Supports `redis://` and `rediss://` URLs, password/ACL authentication, database selection,
 * automatic transparent reconnection on idle socket drops in persistent workers,
 * and deterministic stream injection (`fromStream()`) for offline protocol testing.
 */
final class RedisClient
{
    private const int MAX_BULK_BYTES = 16_777_216;
    private const int MAX_ARRAY_ELEMENTS = 100_000;
    private const int MAX_NESTING_DEPTH = 16;
    private const int MAX_LINE_BYTES = 65_536;

    /** @var resource|null */
    private mixed $stream;

    /** @var ?Closure(): resource */
    private ?Closure $connector;

    /**
     * @param resource             $stream
     * @param ?Closure(): resource $connector
     */
    private function __construct(mixed $stream, ?Closure $connector = null)
    {
        $this->stream = $stream;
        $this->connector = $connector;
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
        $cleanHost = self::validateSocketHost($host);
        if ($port < 1 || $port > 65535) {
            throw new CoreException(sprintf('Invalid Redis port %d.', $port));
        }
        $safeTimeout = is_finite($timeout) ? max(0.05, $timeout) : 3.0;

        $connector = static function () use ($host, $cleanHost, $port, $password, $database, $tls, $safeTimeout, $username): mixed {
            $scheme = $tls ? 'tls' : 'tcp';
            $errno = 0;
            $errstr = '';
            $peerName = trim($cleanHost, '[]');
            $context = $tls
                ? stream_context_create([
                    'ssl' => [
                        'verify_peer' => true,
                        'verify_peer_name' => true,
                        'allow_self_signed' => false,
                        'peer_name' => $peerName,
                        'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
                    ],
                ])
                : stream_context_create();
            $stream = @stream_socket_client(
                sprintf('%s://%s:%d', $scheme, $cleanHost, $port),
                $errno,
                $errstr,
                $safeTimeout,
                STREAM_CLIENT_CONNECT,
                $context,
            );
            if (!is_resource($stream)) {
                throw new CoreException(sprintf('Unable to connect to Redis at %s:%d (%s).', $host, $port, $errstr));
            }

            stream_set_timeout($stream, (int) $safeTimeout, (int) (($safeTimeout - floor($safeTimeout)) * 1_000_000));
            $bootstrap = new self($stream);

            try {
                if (null !== $password && '' !== $password) {
                    if (null !== $username && '' !== $username) {
                        $bootstrap->command('AUTH', $username, $password);
                    } else {
                        $bootstrap->command('AUTH', $password);
                    }
                }
                if ($database > 0) {
                    $bootstrap->command('SELECT', (string) $database);
                }
            } catch (\Throwable $e) {
                @fclose($stream);
                throw $e;
            }

            return $stream;
        };

        /** @var resource $stream */
        $stream = $connector();

        return new self($stream, $connector);
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
     * @param resource             $stream
     * @param ?Closure(): resource $connector Optional reconnect factory for transport-recovery tests
     */
    public static function fromStream(mixed $stream, ?Closure $connector = null): self
    {
        if (!is_resource($stream)) {
            throw new CoreException('RedisClient::fromStream() requires a valid stream resource.');
        }

        return new self($stream, $connector);
    }

    /** Re-establish the Redis TCP/TLS connection when a connector factory is present. */
    public function reconnect(): void
    {
        $connector = $this->connector;
        if (null === $connector) {
            throw new CoreException('Redis client cannot reconnect without a connector factory.');
        }
        $this->close();
        $this->stream = $connector();
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

    /** @var array<string, true> */
    private const array IDEMPOTENT_READ_COMMANDS = [
        'PING' => true,
        'GET' => true,
        'MGET' => true,
        'EXISTS' => true,
        'TTL' => true,
        'PTTL' => true,
        'STRLEN' => true,
        'HGET' => true,
        'HGETALL' => true,
        'HMGET' => true,
        'HEXISTS' => true,
        'SMEMBERS' => true,
        'SISMEMBER' => true,
        'SCARD' => true,
        'ZRANGE' => true,
        'ZRANGEBYSCORE' => true,
        'ZSCORE' => true,
        'ZCARD' => true,
        'LRANGE' => true,
        'LLEN' => true,
        'SCAN' => true,
        'TYPE' => true,
    ];

    public function command(string ...$args): mixed
    {
        $wire = self::encodeCommand(...$args);
        $cmdName = isset($args[0]) ? strtoupper($args[0]) : '';
        $isIdempotent = isset(self::IDEMPOTENT_READ_COMMANDS[$cmdName]);
        $attempts = null !== $this->connector ? 2 : 1;

        for ($attempt = 1; $attempt <= $attempts; ++$attempt) {
            if (!is_resource($this->stream)) {
                if (null !== $this->connector) {
                    $this->reconnect();
                } else {
                    throw new CoreException('Redis connection is closed.');
                }
            }

            try {
                return $this->sendAndRead($wire);
            } catch (CoreException $e) {
                // Only auto-retry idempotent read commands after a transport drop; never replay mutating writes/INCR/EVAL
                if ($attempt < $attempts && null !== $this->connector && $isIdempotent && $this->isTransportError($e)) {
                    $this->reconnect();
                    continue;
                }

                throw $e;
            }
        }

        throw new CoreException('Redis command execution failed.');
    }

    private function sendAndRead(string $wire): mixed
    {
        if (!is_resource($this->stream)) {
            throw new CoreException('Redis connection is closed.');
        }

        $total = strlen($wire);
        $written = 0;
        while ($written < $total) {
            $n = @fwrite($this->stream, substr($wire, $written, 65536));
            if (false === $n || 0 === $n) {
                $this->close();
                throw new CoreException('Failed writing command to Redis stream.');
            }
            $written += $n;
        }

        return $this->readReply();
    }

    private function isTransportError(CoreException $e): bool
    {
        $msg = $e->getMessage();

        return str_contains($msg, 'Failed writing command to Redis stream')
            || str_contains($msg, 'Unexpected EOF while reading Redis reply')
            || str_contains($msg, 'Unexpected EOF while reading Redis bulk string')
            || str_contains($msg, 'Redis connection is closed');
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

    /** Atomically set a key only when it does not already exist. */
    public function setNx(string $key, string $value, int $ttlSeconds = 300): bool
    {
        $reply = $this->command('SET', $key, $value, 'EX', (string) max(1, $ttlSeconds), 'NX');

        return 'OK' === $reply;
    }

    /** Atomically retrieve and delete a key (Redis 6.2+ / Valkey). */
    public function getDel(string $key): ?string
    {
        $reply = $this->command('GETDEL', $key);

        return is_string($reply) ? $reply : null;
    }

    /**
     * Evaluate a Redis Lua script atomically.
     *
     * @param list<string> $keys
     * @param list<string> $args
     */
    public function eval(string $script, array $keys = [], array $args = []): mixed
    {
        return $this->command('EVAL', $script, (string) count($keys), ...$keys, ...$args);
    }

    /** Atomically increment a counter and initialize its TTL on creation (single round-trip Lua). */
    public function incrByWithTtl(string $key, int $delta = 1, int $ttlSeconds = 300): int
    {
        $script = <<<'LUA'
local existed = redis.call('EXISTS', KEYS[1])
local v = redis.call('INCRBY', KEYS[1], tonumber(ARGV[1]))
if existed == 0 or redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end
return v
LUA;
        $reply = $this->eval($script, [$key], [(string) $delta, (string) max(1, $ttlSeconds)]);

        return is_int($reply) ? $reply : 0;
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

    public function hSet(string $key, string $field, string $value): int
    {
        $reply = $this->command('HSET', $key, $field, $value);

        return is_int($reply) ? $reply : 0;
    }

    public function hGet(string $key, string $field): ?string
    {
        $reply = $this->command('HGET', $key, $field);

        return is_string($reply) ? $reply : null;
    }

    public function hDel(string $key, string ...$fields): int
    {
        if ([] === $fields) {
            return 0;
        }
        $reply = $this->command('HDEL', $key, ...$fields);

        return is_int($reply) ? $reply : 0;
    }

    /** @return array<string, string> */
    public function hGetAll(string $key): array
    {
        $reply = $this->command('HGETALL', $key);
        if (!is_array($reply)) {
            return [];
        }
        $out = [];
        $count = count($reply);
        for ($i = 0; $i + 1 < $count; $i += 2) {
            $k = $reply[$i];
            $v = $reply[$i + 1];
            if (is_string($k) && is_string($v)) {
                $out[$k] = $v;
            }
        }

        return $out;
    }

    public function zAdd(string $key, float $score, string $member): int
    {
        $reply = $this->command('ZADD', $key, (string) $score, $member);

        return is_int($reply) ? $reply : 0;
    }

    /** @return list<string> */
    public function zRangeByScore(string $key, string $min, string $max, ?int $limit = null): array
    {
        $args = ['ZRANGEBYSCORE', $key, $min, $max];
        if (null !== $limit && $limit > 0) {
            array_push($args, 'LIMIT', '0', (string) $limit);
        }
        $reply = $this->command(...$args);
        if (!is_array($reply)) {
            return [];
        }
        $out = [];
        foreach ($reply as $item) {
            if (is_string($item)) {
                $out[] = $item;
            }
        }

        return $out;
    }

    public function zRem(string $key, string ...$members): int
    {
        if ([] === $members) {
            return 0;
        }
        $reply = $this->command('ZREM', $key, ...$members);

        return is_int($reply) ? $reply : 0;
    }

    public function zCard(string $key): int
    {
        $reply = $this->command('ZCARD', $key);

        return is_int($reply) ? $reply : 0;
    }

    public function zRemRangeByRank(string $key, int $start, int $stop): int
    {
        $reply = $this->command('ZREMRANGEBYRANK', $key, (string) $start, (string) $stop);

        return is_int($reply) ? $reply : 0;
    }

    public function hIncrBy(string $key, string $field, int $delta): int
    {
        $reply = $this->command('HINCRBY', $key, $field, (string) $delta);

        return is_int($reply) ? $reply : 0;
    }

    public function publish(string $channel, string $message): int
    {
        $reply = $this->command('PUBLISH', $channel, $message);

        return is_int($reply) ? $reply : 0;
    }

    public function close(): void
    {
        if (is_resource($this->stream)) {
            fclose($this->stream);
        }
        $this->stream = null;
    }

    /**
     * Non-blocking iterative SCAN cursor query.
     *
     * @return array{0: string, 1: list<string>}
     */
    public function scan(string $cursor, ?string $match = null, int $count = 500): array
    {
        $args = [$cursor];
        if (null !== $match) {
            $args[] = 'MATCH';
            $args[] = $match;
        }
        $args[] = 'COUNT';
        $args[] = (string) max(1, $count);

        $reply = $this->command('SCAN', ...$args);
        if (!is_array($reply) || count($reply) < 2) {
            return ['0', []];
        }
        $nextCursor = is_scalar($reply[0] ?? null) ? (string) $reply[0] : '0';
        $keys = [];
        if (is_array($reply[1] ?? null)) {
            foreach ($reply[1] as $item) {
                if (is_string($item)) {
                    $keys[] = $item;
                }
            }
        }

        return [$nextCursor, $keys];
    }

    private function readReply(int $depth = 0, int &$totalElements = 0, int &$totalBytes = 0): mixed
    {
        if ($depth > self::MAX_NESTING_DEPTH) {
            $this->close();
            throw new CoreException('Redis RESP nesting depth exceeded maximum limit.');
        }
        if (!is_resource($this->stream)) {
            throw new CoreException('Redis connection is closed.');
        }

        $line = @fgets($this->stream, self::MAX_LINE_BYTES + 1);
        if (false === $line || '' === $line) {
            $this->close();
            throw new CoreException('Unexpected EOF while reading Redis reply.');
        }
        if (!str_ends_with($line, "\n")) {
            $this->close();
            throw new CoreException('Redis RESP reply line exceeded maximum length or ended prematurely.');
        }

        $totalBytes += strlen($line);
        if ($totalBytes > self::MAX_BULK_BYTES * 2) {
            $this->close();
            throw new CoreException('Redis RESP cumulative reply size exceeded maximum bound.');
        }

        $prefix = $line[0];
        $payload = rtrim(substr($line, 1), "\r\n");

        return match ($prefix) {
            '+' => $payload,
            '-' => throw new CoreException('Redis error: ' . $payload),
            ':' => $this->parseRespInt($payload),
            '_' => null,
            '#' => 't' === $payload,
            ',' => (float) $payload,
            '$' => $this->readBulkString($this->parseRespInt($payload), $totalBytes),
            '*' => $this->readArray($this->parseRespInt($payload), $depth, $totalElements, $totalBytes),
            default => (function () use ($prefix): never {
                $this->close();
                throw new CoreException(sprintf('Unsupported Redis RESP prefix "%s".', $prefix));
            })(),
        };
    }

    private function parseRespInt(string $payload): int
    {
        if (1 !== preg_match('/\A-?\d+\z/', $payload)) {
            $this->close();
            throw new CoreException('Malformed non-numeric Redis RESP integer payload.');
        }

        return (int) $payload;
    }

    private function readBulkString(int $length, int &$totalBytes): ?string
    {
        if ($length < 0) {
            return null;
        }
        if ($length > self::MAX_BULK_BYTES) {
            $this->close();
            throw new CoreException(sprintf('Redis bulk string size %d exceeds maximum bound of %d bytes.', $length, self::MAX_BULK_BYTES));
        }
        $totalBytes += $length + 2;
        if ($totalBytes > self::MAX_BULK_BYTES * 2) {
            $this->close();
            throw new CoreException('Redis RESP cumulative reply size exceeded maximum bound.');
        }
        if (!is_resource($this->stream)) {
            throw new CoreException('Redis connection is closed.');
        }

        $remaining = $length + 2; // payload + trailing CRLF
        $buf = '';
        while ($remaining > 0) {
            $chunk = @fread($this->stream, $remaining);
            if (false === $chunk || '' === $chunk) {
                $this->close();
                throw new CoreException('Unexpected EOF while reading Redis bulk string.');
            }
            $buf .= $chunk;
            $remaining -= strlen($chunk);
        }

        if ("\r\n" !== substr($buf, $length, 2)) {
            $this->close();
            throw new CoreException('Malformed Redis bulk string terminator (missing CRLF).');
        }

        return substr($buf, 0, $length);
    }

    /** @return list<mixed>|null */
    private function readArray(int $count, int $depth, int &$totalElements, int &$totalBytes): ?array
    {
        if ($count < 0) {
            return null;
        }
        if ($count > self::MAX_ARRAY_ELEMENTS) {
            $this->close();
            throw new CoreException(sprintf('Redis array length %d exceeds maximum bound of %d elements.', $count, self::MAX_ARRAY_ELEMENTS));
        }
        $totalElements += $count;
        if ($totalElements > self::MAX_ARRAY_ELEMENTS) {
            $this->close();
            throw new CoreException('Redis cumulative nested array element count exceeded maximum bound.');
        }
        $items = [];
        for ($i = 0; $i < $count; ++$i) {
            $items[] = $this->readReply($depth + 1, $totalElements, $totalBytes);
        }

        return $items;
    }

    private static function validateSocketHost(string $host): string
    {
        if (false !== strpbrk($host, "\r\n\0")) {
            throw new CoreException('Unsafe Redis host rejected.');
        }
        $trimmed = trim($host);
        if ('' === $trimmed || strlen($trimmed) > 255 || false !== strpbrk($trimmed, " \t/?#@%\\")) {
            throw new CoreException('Unsafe Redis host rejected.');
        }
        if (str_starts_with($trimmed, '[') && str_ends_with($trimmed, ']')) {
            $inner = substr($trimmed, 1, -1);
            if (false === filter_var($inner, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                throw new CoreException('Invalid bracketed IPv6 Redis host.');
            }

            return '[' . strtolower($inner) . ']';
        }
        if (false !== filter_var($trimmed, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return '[' . strtolower($trimmed) . ']';
        }
        if (false !== filter_var($trimmed, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $trimmed;
        }
        if (1 !== preg_match('/\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\z/', $trimmed)) {
            throw new CoreException('Unsafe Redis host rejected.');
        }

        return $trimmed;
    }
}
