<?php

declare(strict_types=1);

namespace Kongono\Core\Graph;

/** Machine-readable route node for ApplicationGraph introspection and AI tooling. */
final readonly class RouteNode
{
    /** @param list<string> $methods */
    public function __construct(
        public array $methods,
        public string $path,
        public string $handler,
        public ?string $name = null,
    ) {}

    /** @return array{methods: list<string>, path: string, handler: string, name: ?string} */
    public function toArray(): array
    {
        return [
            'methods' => $this->methods,
            'path' => $this->path,
            'handler' => $this->handler,
            'name' => $this->name,
        ];
    }
}
