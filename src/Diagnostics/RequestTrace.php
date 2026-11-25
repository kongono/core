<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/**
 * Request-scoped, secret-scrubbed Dev X-Ray execution trace (`APP_DEBUG=true` only).
 *
 * Shows developers and AI agents exactly how the request traveled through middleware,
 * which route/handler matched, which input keys arrived (never secret values), and
 * how many milliseconds elapsed before failure. Never sent to production clients.
 */
final readonly class RequestTrace
{
    /**
     * @param list<string>          $middleware
     * @param array<string, string> $routeParams
     * @param list<string>          $queryKeys
     * @param list<string>          $inputKeys
     */
    public function __construct(
        public string $referenceId,
        public string $method,
        public string $path,
        public ?string $matchedRoute = null,
        public ?string $matchedHandler = null,
        public array $middleware = [],
        public array $routeParams = [],
        public array $queryKeys = [],
        public array $inputKeys = [],
        public float $elapsedMs = 0.0,
    ) {}

    /**
     * @return array{
     *     reference_id: string,
     *     method: string,
     *     path: string,
     *     matched_route: ?string,
     *     matched_handler: ?string,
     *     middleware: list<string>,
     *     route_params: array<string, string>,
     *     query_keys: list<string>,
     *     input_keys: list<string>,
     *     elapsed_ms: float
     * }
     */
    public function toArray(): array
    {
        $safeParams = [];
        foreach ($this->routeParams as $k => $v) {
            $safeParams[$k] = SecretScrubber::isSensitiveKey($k) ? '[REDACTED]' : SecretScrubber::scrub($v);
        }

        return [
            'reference_id' => $this->referenceId,
            'method' => strtoupper($this->method),
            'path' => SecretScrubber::scrub($this->path),
            'matched_route' => null !== $this->matchedRoute ? SecretScrubber::scrub($this->matchedRoute) : null,
            'matched_handler' => $this->matchedHandler,
            'middleware' => $this->middleware,
            'route_params' => $safeParams,
            'query_keys' => $this->queryKeys,
            'input_keys' => $this->inputKeys,
            'elapsed_ms' => round($this->elapsedMs, 2),
        ];
    }

    public function toMarkdown(): string
    {
        $safe = $this->toArray();
        $pipeline = [] !== $safe['middleware']
            ? implode(' -> ', $safe['middleware'])
            : '(none)';
        if (null !== $safe['matched_handler']) {
            $pipeline .= ' -> ' . $safe['matched_handler'];
        }

        $lines = [
            '## Execution Trace (Dev X-Ray)',
            sprintf('- **Reference ID:** `%s`', $safe['reference_id']),
            sprintf('- **Request:** `%s %s` (%.2f ms)', $safe['method'], $safe['path'], $safe['elapsed_ms']),
            sprintf('- **Matched Route:** `%s`', $safe['matched_route'] ?? 'none (failed before route match)'),
            sprintf('- **Pipeline:** `%s`', $pipeline),
        ];

        if ([] !== $safe['route_params']) {
            $pairs = [];
            foreach ($safe['route_params'] as $k => $v) {
                $pairs[] = sprintf('%s=%s', $k, $v);
            }
            $lines[] = sprintf('- **Route Params:** `%s`', implode(', ', $pairs));
        }

        if ([] !== $safe['query_keys']) {
            $lines[] = sprintf('- **Query Keys:** `%s`', implode(', ', $safe['query_keys']));
        }

        if ([] !== $safe['input_keys']) {
            $lines[] = sprintf('- **Body Input Keys:** `%s`', implode(', ', $safe['input_keys']));
        }

        return implode("\n", $lines);
    }
}
