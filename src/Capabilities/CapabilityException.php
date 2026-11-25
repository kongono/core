<?php

declare(strict_types=1);

namespace Kongono\Core\Capabilities;

use Kongono\Core\CoreException;
use Kongono\Core\Diagnostics\Diagnostic;
use Kongono\Core\Diagnostics\Disclosure;
use Throwable;

/**
 * Thrown when a route exceeds its declared least-privilege execution capability sandbox
 * (`#[ReadOnlyDb]`, `#[NoOutboundHttp]`, `#[MaxQueries]`, or `#[MaxAiCost]`).
 */
final class CapabilityException extends CoreException
{
    public function __construct(
        public readonly string $capability,
        string $message,
        ?Diagnostic $diagnostic = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            message: $message,
            diagnostic: $diagnostic ?? new Diagnostic(
                id: 'KGN-CAP-' . strtoupper((string) preg_replace('/[^A-Za-z0-9]+/', '-', trim($capability, '#[]()'))),
                title: sprintf('Route capability "%s" blocked an unauthorized operation', $capability),
                remediation: sprintf('Remove the disallowed operation from this handler or adjust the `%s` attribute on the route.', $capability),
                fields: ['capability' => ['value' => $capability, 'disclosure' => Disclosure::Safe]],
            ),
            previous: $previous,
        );
    }
}
