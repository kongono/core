<?php

declare(strict_types=1);

namespace Kongono\Core;

enum KernelState: string
{
    case Unbooted = 'unbooted';
    case Booted = 'booted';
    case Shutdown = 'shutdown';
}
