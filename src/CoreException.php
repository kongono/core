<?php

declare(strict_types=1);

namespace Kongono\Core;

use Kongono\Core\Diagnostics\Diagnostic;
use RuntimeException;
use Throwable;

class CoreException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?Diagnostic $diagnostic = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
