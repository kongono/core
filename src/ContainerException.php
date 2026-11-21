<?php

declare(strict_types=1);

namespace Kongono\Core;

use Psr\Container\ContainerExceptionInterface;

final class ContainerException extends CoreException implements ContainerExceptionInterface {}
