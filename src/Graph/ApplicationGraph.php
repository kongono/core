<?php

declare(strict_types=1);

namespace Kongono\Core\Graph;

/**
 * Live, machine-readable map of a Kongono application.
 *
 * Powers `kongo graph`, `kongo routes`, and gives Oshie, Chie, and Hantei exact
 * structural knowledge of the application without guessing.
 */
final readonly class ApplicationGraph
{
    /**
     * @param list<RouteNode>   $routes
     * @param list<ServiceNode> $services
     * @param list<string>      $middleware
     * @param list<string>      $views
     * @param list<string>      $configKeys
     */
    public function __construct(
        public string $appName,
        public string $basePath,
        public array $routes = [],
        public array $services = [],
        public array $middleware = [],
        public array $views = [],
        public array $configKeys = [],
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'app' => $this->appName,
            'base_path' => $this->basePath,
            'routes' => array_map(static fn(RouteNode $r): array => $r->toArray(), $this->routes),
            'services' => array_map(static fn(ServiceNode $s): array => $s->toArray(), $this->services),
            'middleware' => $this->middleware,
            'views' => $this->views,
            'config_keys' => $this->configKeys,
        ];
    }

    public function toJson(bool $pretty = true): string
    {
        $flags = JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES;
        if ($pretty) {
            $flags |= JSON_PRETTY_PRINT;
        }

        return json_encode($this->toArray(), $flags);
    }
}
