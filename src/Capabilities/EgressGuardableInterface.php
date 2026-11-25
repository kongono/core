<?php

declare(strict_types=1);

namespace Kongono\Core\Capabilities;

use Closure;

/**
 * Contract for outbound HTTP clients that support scoped pre-request egress guards
 * (used by Kongono's `#[NoOutboundHttp]` route capability sandbox).
 */
interface EgressGuardableInterface
{
    /**
     * Register a pre-request egress guard invoked BEFORE DNS resolution or socket connect.
     * Returns an unsubscribe closure to restore clean persistent-worker state.
     *
     * @param Closure(string): void $guard
     * @return Closure(): void
     */
    public function guardBeforeRequest(Closure $guard): Closure;
}
