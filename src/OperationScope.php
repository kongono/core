<?php

declare(strict_types=1);

namespace Kongono\Core;

use Closure;
use Throwable;

/** Represents one isolated operation (e.g. HTTP request, job, CLI command) with deterministic cleanup. */
final class OperationScope
{
    /** @var list<Closure(): void> */
    private array $cleanups = [];

    private bool $ended = false;

    public function __construct(
        public readonly string $id,
    ) {}

    /** @param Closure(): void $cleanup */
    public function defer(Closure $cleanup): void
    {
        if ($this->ended) {
            throw new CoreException('Cannot register cleanup on an ended operation scope.');
        }
        $this->cleanups[] = $cleanup;
    }

    public function isEnded(): bool
    {
        return $this->ended;
    }

    /** Runs deferred cleanups in LIFO order. */
    public function end(): void
    {
        if ($this->ended) {
            return;
        }
        $this->ended = true;

        $firstFailure = null;
        for ($i = count($this->cleanups) - 1; $i >= 0; --$i) {
            try {
                ($this->cleanups[$i])();
            } catch (Throwable $failure) {
                $firstFailure ??= $failure;
            }
        }
        $this->cleanups = [];

        if (null !== $firstFailure) {
            throw new CoreException('Operation scope cleanup failed.', previous: $firstFailure);
        }
    }
}
