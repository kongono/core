<?php

declare(strict_types=1);

namespace Kongono\Core\Capabilities;

use Closure;

/**
 * Contract for database connections that support scoped pre-execution SQL guards
 * (used by Kongono's `#[ReadOnlyDb]` and `#[MaxQueries]` route capability sandboxes).
 */
interface QueryGuardableInterface
{
    /**
     * Register a pre-execution SQL guard invoked BEFORE every query/statement runs.
     * Returns an unsubscribe closure to restore clean persistent-worker state.
     *
     * @param Closure(string): void $guard
     * @return Closure(): void
     */
    public function guardBeforeQuery(Closure $guard): Closure;
}
