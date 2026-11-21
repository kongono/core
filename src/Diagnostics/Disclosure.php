<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

enum Disclosure: string
{
    /** Safe for user-facing logs, CLI, and external AI diagnostic context. */
    case Safe = 'safe';

    /** Internal operational detail; redacted before external disclosure or AI prompts. */
    case Protected = 'protected';

    /** Secret-bearing material; never emitted or logged. */
    case Forbidden = 'forbidden';
}
