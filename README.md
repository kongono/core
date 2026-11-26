# Kongono Core (`kongono/core`)

> **Read-only subtree split** of [`kongono/framework`](https://github.com/kongono/framework). Open issues and pull requests in the main monorepo.

Zero-legacy PHP 8.5.13+ persistent-runtime kernel, PSR-11 DI container, RFC 9562 `Id\Uuid` (`Uuid::v7()` / `Uuid::v4()`), typed `Config`, `EnvLoader`, project-aware nondisclosing `EnvExampleGenerator`, `SecretScrubber` diagnostics, pure-PHP caches (`MemoryCache`, `FileCache`, `RedisClient` + `RedisCache`), Fiber `Async`, `FeatureManager`, `Retry`/`CircuitBreaker`, `Metrics`/`Tracer`, and `ApplicationGraph` — depending only on 3 PSR interface packages.

## Installation

```bash
composer require kongono/core
```

## Example

```php
<?php

declare(strict_types=1);

use Kongono\Core\Cache\MemoryCache;
use Kongono\Core\Config;
use Kongono\Core\Diagnostics\SecretScrubber;
use Kongono\Core\EnvLoader;

EnvLoader::load(__DIR__ . '/.env');

$cache = new MemoryCache();
$cache->set('greeting', 'hello', 60);

$safe = SecretScrubber::scrub('Authorization: Bearer secret-token-123');
// "Authorization: Bearer [REDACTED]"
```

## Documentation & License

- Full documentation: https://kongono.com/docs.html
- Monorepo & issues: https://github.com/kongono/framework
- License: MIT
