<?php

declare(strict_types=1);

namespace Kongono\Core\Graph;

/** Machine-readable service binding node for ApplicationGraph introspection. */
final readonly class ServiceNode
{
    /** @param 'transient'|'singleton'|'scoped' $lifetime */
    public function __construct(
        public string $id,
        public string $lifetime,
    ) {}

    /** @return array{id: string, lifetime: string} */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'lifetime' => $this->lifetime,
        ];
    }
}
