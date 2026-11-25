<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/**
 * Secret-scrubbed, zero-credential snapshot of a production or local runtime incident,
 * indexed by Kongono's opaque `KGN-YYYYMMDD-XXXXXXXX` Reference ID for one-command local replay
 * (`kongo incident:replay`) and PHPUnit 13 regression test generation (`kongo incident:test`).
 */
final readonly class IncidentRecord
{
    /** @var list<string> */
    private const array FORBIDDEN_HEADERS = [
        'authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token',
        'proxy-authorization', 'x-csrf-token', 'x-xsrf-token', 'x-kongono-key',
        'x-goog-api-key', 'x-session-token', 'x-access-token', 'stripe-signature',
        'x-amz-security-token', 'x-amz-signature', 'x-kongono-signature',
    ];

    /** @var list<string> */
    private const array SENSITIVE_KEY_FRAGMENTS = [
        'password', 'passwd', 'passphrase', 'secret', 'token', 'api_key', 'apikey',
        'private_key', 'credit_card', 'card_number', 'cvv', 'cvc', 'ssn', '_csrf',
    ];

    /**
     * @param array<string, mixed>  $query
     * @param array<string, string> $headers
     * @param array<string, mixed>  $body
     * @param array<string, mixed>  $explanation
     * @param ?array<string, mixed> $executionTrace
     */
    public function __construct(
        public string $reference,
        public string $occurredAt,
        public string $appName,
        public int $statusCode,
        public string $method,
        public string $path,
        public array $query,
        public array $headers,
        public array $body,
        public string $contentType,
        public array $explanation,
        public ?array $executionTrace = null,
    ) {}

    private const int MAX_HEADERS = 64;
    private const int MAX_HEADER_VALUE_BYTES = 512;
    private const int MAX_PAYLOAD_NODES = 256;
    private const int MAX_ARRAY_ENTRIES = 64;

    /**
     * Sanitize HTTP headers by dropping auth/cookie/secret headers and scrubbing values.
     *
     * @param array<string, array<string>|string> $rawHeaders
     * @return array<string, string>
     */
    public static function sanitizeHeaders(array $rawHeaders): array
    {
        $safe = [];
        $count = 0;
        foreach ($rawHeaders as $name => $val) {
            if ($count >= self::MAX_HEADERS) {
                $safe['_truncated'] = 'true';
                break;
            }
            $lower = strtolower($name);
            if (in_array($lower, self::FORBIDDEN_HEADERS, true) || SecretScrubber::isSensitiveKey($name)) {
                continue;
            }
            $joined = is_array($val) ? implode(', ', array_slice($val, 0, 16)) : $val;
            $safe[substr($name, 0, 128)] = substr(SecretScrubber::scrub(substr($joined, 0, 2048)), 0, self::MAX_HEADER_VALUE_BYTES);
            ++$count;
        }

        return $safe;
    }

    /**
     * Recursively redact sensitive fields and scrub secrets from query/body arrays with hard node & entry bounds.
     *
     * @param array<mixed> $data
     * @return array<string, mixed>
     */
    public static function sanitizePayload(array $data, int $depth = 0): array
    {
        $remaining = self::MAX_PAYLOAD_NODES;

        return self::sanitizePayloadBounded($data, $depth, $remaining);
    }

    /**
     * @param array<mixed> $data
     * @return array<string, mixed>
     */
    private static function sanitizePayloadBounded(array $data, int $depth, int &$remainingNodes): array
    {
        if ($depth > 6 || $remainingNodes <= 0) {
            return ['_truncated' => true];
        }

        $out = [];
        $entriesAtLevel = 0;
        foreach ($data as $key => $value) {
            if ($entriesAtLevel >= self::MAX_ARRAY_ENTRIES || $remainingNodes <= 0) {
                $out['_truncated'] = true;
                break;
            }
            --$remainingNodes;
            ++$entriesAtLevel;

            $keyStr = substr((string) $key, 0, 128);
            $lower = strtolower($keyStr);
            $isSensitive = SecretScrubber::isSensitiveKey($keyStr);
            if (!$isSensitive) {
                foreach (self::SENSITIVE_KEY_FRAGMENTS as $frag) {
                    if (str_contains($lower, $frag)) {
                        $isSensitive = true;
                        break;
                    }
                }
            }

            if ($isSensitive) {
                $out[$keyStr] = '[REDACTED]';
            } elseif (is_array($value)) {
                $out[$keyStr] = self::sanitizePayloadBounded($value, $depth + 1, $remainingNodes);
            } elseif (is_string($value)) {
                $scrubbed = SecretScrubber::scrub(substr($value, 0, 4096));
                $out[$keyStr] = substr($scrubbed, 0, 1024);
            } elseif (is_int($value) || is_float($value) || is_bool($value) || null === $value) {
                $out[$keyStr] = $value;
            } else {
                $out[$keyStr] = '[NON-SCALAR]';
            }
        }

        return $out;
    }

    /**
     * @return array{
     *     reference: string,
     *     occurred_at: string,
     *     app_name: string,
     *     status_code: int,
     *     method: string,
     *     path: string,
     *     query: array<string, mixed>,
     *     headers: array<string, string>,
     *     body: array<string, mixed>,
     *     content_type: string,
     *     explanation: array<string, mixed>,
     *     execution_trace: ?array<string, mixed>
     * }
     */
    public function toArray(): array
    {
        return [
            'reference' => $this->reference,
            'occurred_at' => $this->occurredAt,
            'app_name' => $this->appName,
            'status_code' => $this->statusCode,
            'method' => $this->method,
            'path' => $this->path,
            'query' => $this->query,
            'headers' => $this->headers,
            'body' => $this->body,
            'content_type' => $this->contentType,
            'explanation' => $this->explanation,
            'execution_trace' => $this->executionTrace,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        /** @var array<string, mixed> $query */
        $query = is_array($data['query'] ?? null) ? $data['query'] : [];
        /** @var array<string, string> $headers */
        $headers = [];
        if (is_array($data['headers'] ?? null)) {
            foreach ($data['headers'] as $k => $v) {
                if (is_string($k) && is_string($v)) {
                    $headers[$k] = $v;
                }
            }
        }
        /** @var array<string, mixed> $body */
        $body = is_array($data['body'] ?? null) ? $data['body'] : [];
        /** @var array<string, mixed> $explanation */
        $explanation = is_array($data['explanation'] ?? null) ? $data['explanation'] : [];
        /** @var ?array<string, mixed> $trace */
        $trace = is_array($data['execution_trace'] ?? null) ? $data['execution_trace'] : null;

        return new self(
            reference: is_string($data['reference'] ?? null) ? $data['reference'] : '',
            occurredAt: is_string($data['occurred_at'] ?? null) ? $data['occurred_at'] : '',
            appName: is_string($data['app_name'] ?? null) ? $data['app_name'] : 'Kongono App',
            statusCode: is_int($data['status_code'] ?? null) ? $data['status_code'] : 500,
            method: is_string($data['method'] ?? null) ? $data['method'] : 'GET',
            path: is_string($data['path'] ?? null) ? $data['path'] : '/',
            query: $query,
            headers: $headers,
            body: $body,
            contentType: is_string($data['content_type'] ?? null) ? $data['content_type'] : '',
            explanation: $explanation,
            executionTrace: $trace,
        );
    }
}
