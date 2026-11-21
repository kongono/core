<?php

declare(strict_types=1);

namespace Kongono\Core;

use Psr\Container\NotFoundExceptionInterface;

final class NotFoundException extends CoreException implements NotFoundExceptionInterface {}
