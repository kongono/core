<?php

declare(strict_types=1);

namespace Kongono\Core\Tests;

use Kongono\Core\Async\Async;
use Kongono\Core\Cache\FileCache;
use Kongono\Core\Cache\MemoryCache;
use Kongono\Core\Cache\RedisCache;
use Kongono\Core\Cache\RedisClient;
use Kongono\Core\Config;
use Kongono\Core\Container;
use Kongono\Core\ContainerException;
use Kongono\Core\CoreException;
use Kongono\Core\Diagnostics\Diagnostic;
use Kongono\Core\Diagnostics\Disclosure;
use Kongono\Core\Diagnostics\SecretScrubber;
use Kongono\Core\EnvLoader;
use Kongono\Core\Events\EventDispatcher;
use Kongono\Core\Features\FeatureManager;
use Kongono\Core\Graph\ApplicationGraph;
use Kongono\Core\Graph\RouteNode;
use Kongono\Core\Graph\ServiceNode;
use Kongono\Core\Health\HealthCheck;
use Kongono\Core\I18n\Translator;
use Kongono\Core\Kernel;
use Kongono\Core\KernelState;
use Kongono\Core\Log\Logger;
use Kongono\Core\Notifications\MemoryNotificationChannel;
use Kongono\Core\Notifications\Notification;
use Kongono\Core\Notifications\NotificationChannelInterface;
use Kongono\Core\Notifications\NotificationDispatcher;
use Kongono\Core\OperationScope;
use Kongono\Core\Resilience\CircuitBreaker;
use Kongono\Core\Resilience\CircuitState;
use Kongono\Core\Resilience\Retry;
use Kongono\Core\Telemetry\Metrics;
use Kongono\Core\Telemetry\Tracer;
use PHPUnit\Framework\TestCase;
use stdClass;

final class CoreTest extends TestCase
{
    public function testKernelRunsOperationsWithLifoCleanupAndShutdownGuard(): void
    {
        $kernel = new Kernel();
        self::assertSame(KernelState::Unbooted, $kernel->state());
        $kernel->boot();
        self::assertSame(KernelState::Booted, $kernel->state());

        $log = [];
        $result = $kernel->runOperation(static function (OperationScope $scope) use (&$log): string {
            $scope->defer(static function () use (&$log): void {
                $log[] = 'first';
            });
            $scope->defer(static function () use (&$log): void {
                $log[] = 'second';
            });

            return $scope->id;
        });

        self::assertSame('op-1', $result);
        self::assertSame(['second', 'first'], $log);
        self::assertSame(0, $kernel->activeOperationCount());

        $scope = $kernel->beginOperation();
        try {
            $kernel->shutdown();
            self::fail('Expected shutdown to fail while operation is active.');
        } catch (CoreException) {
            // Expected
        }
        $kernel->endOperation($scope);
        $kernel->shutdown();
        self::assertSame(KernelState::Shutdown, $kernel->state());
    }

    public function testContainerSupportsSingletonScopedTransientAutowiringAndCycleDetection(): void
    {
        $container = new Container();
        $container->singleton('single', static fn(): stdClass => new stdClass());
        $container->scoped('req', static fn(): stdClass => new stdClass());
        $container->bind('trans', static fn(): stdClass => new stdClass());

        self::assertSame($container->get('single'), $container->get('single'));
        $req1 = $container->get('req');
        self::assertSame($req1, $container->get('req'));
        $container->resetScope();
        self::assertNotSame($req1, $container->get('req'));
        self::assertNotSame($container->get('trans'), $container->get('trans'));

        $container->bind('a', static fn(Container $c): mixed => $c->get('b'));
        $container->bind('b', static fn(Container $c): mixed => $c->get('a'));

        $this->expectException(ContainerException::class);
        $container->get('a');
    }

    public function testConfigDotAccessAndTyping(): void
    {
        $config = new Config([
            'app' => ['name' => 'Kongono', 'debug' => 'true', 'port' => '8080'],
        ]);

        self::assertTrue($config->has('app.name'));
        self::assertFalse($config->has('app.missing'));
        self::assertSame('Kongono', $config->string('app.name'));
        self::assertTrue($config->bool('app.debug'));
        self::assertSame(8080, $config->int('app.port'));
    }

    public function testDiagnosticExposesOnlySafeFieldsAndScrubsSecrets(): void
    {
        $diag = new Diagnostic(
            id: 'KGN-TEST-001',
            title: 'Auth error',
            remediation: 'Check token',
            fields: [
                'hint' => ['value' => 'Failed with Bearer eyJhbGciOiJIUzI1NiJ9.abc.def and sk-proj-1234567890abcdef1234', 'disclosure' => Disclosure::Safe],
                'raw_secret' => ['value' => 'super-secret-value', 'disclosure' => Disclosure::Protected],
            ],
        );

        $safe = $diag->toSafeArray();
        self::assertArrayHasKey('hint', $safe['fields']);
        self::assertArrayNotHasKey('raw_secret', $safe['fields']);
        self::assertStringNotContainsString('sk-proj-1234567890abcdef1234', (string) $safe['fields']['hint']);
        self::assertStringContainsString('[REDACTED]', (string) $safe['fields']['hint']);
        self::assertStringNotContainsString('secret123', SecretScrubber::scrub('password=secret123'));

        // URI/DSN credentials, webhook signing secrets, and non-secret URLs
        self::assertSame(
            'postgres://[REDACTED]@db.internal:5432/prod',
            SecretScrubber::scrub('postgres://admin:super_secret_pw@db.internal:5432/prod'),
        );
        self::assertSame(
            'mysql://[REDACTED]@127.0.0.1:3306/app',
            SecretScrubber::scrub('mysql://root:hunter2@127.0.0.1:3306/app'),
        );
        self::assertSame(
            'redis://[REDACTED]@127.0.0.1:6379/0',
            SecretScrubber::scrub('redis://:cachepass99@127.0.0.1:6379/0'),
        );
        self::assertSame(
            'sig=[REDACTED]',
            SecretScrubber::scrub('sig=whsec_stripe_demo_4a89025693b85fce49f6'),
        );
        self::assertSame(
            'https://example.com:8443/@ada',
            SecretScrubber::scrub('https://example.com:8443/@ada'),
        );
        self::assertSame(
            'redis://127.0.0.1:6379/0',
            SecretScrubber::scrub('redis://127.0.0.1:6379/0'),
        );

        // v1.2.0: key-preserving scrub (zero double brackets), PEM keys, Stripe live keys, and recursive scrubArray()
        self::assertSame(
            'OPENAI_API_KEY=[REDACTED]',
            SecretScrubber::scrub('OPENAI_API_KEY=sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'),
        );
        self::assertSame(
            'STRIPE_WEBHOOK_SECRET=[REDACTED]',
            SecretScrubber::scrub('STRIPE_WEBHOOK_SECRET=whsec_9f8e7d6c5b4a3210fedcba9876543210'),
        );
        self::assertSame(
            'Authorization: Bearer [REDACTED]',
            SecretScrubber::scrub('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def'),
        );
        self::assertSame(
            '[REDACTED_PRIVATE_KEY]',
            SecretScrubber::scrub("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"),
        );

        $scrubbedArr = SecretScrubber::scrubArray([
            'user' => 'maya',
            'password' => 'hunter2',
            'stripe_api_key' => 'sk_live_1234567890abcdef1234',
            'nested' => ['dsn' => 'postgres://admin:secretpw@db:5432/app'],
        ]);
        self::assertSame('maya', $scrubbedArr['user']);
        self::assertSame('[REDACTED]', $scrubbedArr['password']);
        self::assertSame('[REDACTED]', $scrubbedArr['stripe_api_key']);
        self::assertIsArray($scrubbedArr['nested']);
        self::assertSame('postgres://[REDACTED]@db:5432/app', $scrubbedArr['nested']['dsn']);
    }

    public function testEventDispatcherPreservesOrderAndBlocksReentrancy(): void
    {
        $dispatcher = new EventDispatcher();
        $order = [];
        $dispatcher->listen(stdClass::class, static function (stdClass $e) use (&$order): void {
            $order[] = 'a';
        });
        $dispatcher->listen(stdClass::class, static function (stdClass $e) use (&$order): void {
            $order[] = 'b';
        });

        $dispatcher->dispatch(new stdClass());
        self::assertSame(['a', 'b'], $order);

        $reentrant = new EventDispatcher();
        $reentrant->listen(stdClass::class, static function (stdClass $e) use ($reentrant): void {
            $reentrant->dispatch($e);
        });

        $this->expectException(CoreException::class);
        $reentrant->dispatch(new stdClass());
    }

    public function testApplicationGraphSerializesToJson(): void
    {
        $graph = new ApplicationGraph(
            appName: 'Demo',
            basePath: '/app',
            routes: [new RouteNode(['GET'], '/', 'HomeController::index', 'home')],
            services: [new ServiceNode('App\\Repo', 'singleton')],
            middleware: ['App\\TimingMiddleware'],
            views: ['home'],
            configKeys: ['app'],
        );

        $decoded = json_decode($graph->toJson(), true, 32, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertSame('Demo', $decoded['app']);
        self::assertCount(1, $decoded['routes']);
    }

    public function testEnvLoaderLoggerAndCachesWork(): void
    {
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kongono-core-test-' . bin2hex(random_bytes(5));
        mkdir($tmp, 0o777, true);
        $envFile = $tmp . DIRECTORY_SEPARATOR . '.env';
        file_put_contents($envFile, "KONGONO_TEST_FOO=\"hello world\"\n# comment\nKONGONO_TEST_NUM=42\n");

        try {
            $loaded = EnvLoader::load($envFile, overwrite: true);
            self::assertSame('hello world', $loaded['KONGONO_TEST_FOO']);
            self::assertSame('42', Config::env('KONGONO_TEST_NUM'));

            $logger = new Logger('test', retainInMemory: true);
            $logger->error('Failed for {user} with sk-proj-1234567890abcdef1234', [
                'user' => 'ada',
                'api_key' => 'super-secret',
            ]);
            $records = $logger->records();
            self::assertCount(1, $records);
            self::assertStringContainsString('ada', $records[0]['message']);
            self::assertStringNotContainsString('sk-proj-1234567890abcdef1234', $records[0]['message']);
            self::assertSame('[REDACTED]', $records[0]['context']['api_key']);

            $memCache = new MemoryCache(maxEntries: 2);
            $memCache->set('k1', 'v1', ttlSeconds: 60, now: 100);
            self::assertSame('v1', $memCache->get('k1', null, now: 120));
            self::assertNull($memCache->get('k1', null, now: 161));

            $fileCache = new FileCache($tmp . DIRECTORY_SEPARATOR . 'cache');
            $computed = $fileCache->remember('answer', 60, static fn(): int => 42);
            self::assertSame(42, $computed);
            self::assertSame(42, $fileCache->get('answer'));
            $fileCache->clear();
            self::assertFalse($fileCache->has('answer'));
        } finally {
            foreach (glob($tmp . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR . '*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($tmp . DIRECTORY_SEPARATOR . 'cache');
            @unlink($envFile);
            @rmdir($tmp);
        }
    }

    public function testMetricsPrometheusExportAndTracerServerTiming(): void
    {
        $metrics = new Metrics();
        $metrics->increment('kongono_http_requests_total', ['method' => 'GET', 'status' => '200']);
        $metrics->increment('kongono_http_requests_total', ['method' => 'GET', 'status' => '200']);
        $metrics->gauge('kongono_active_workers', 4.0);
        $metrics->observe('kongono_request_ms', 12.5, ['route' => 'home']);

        self::assertSame(2.0, $metrics->counterValue('kongono_http_requests_total', ['status' => '200', 'method' => 'GET']));
        $prom = $metrics->toPrometheus();
        self::assertStringContainsString('kongono_http_requests_total{method="GET",status="200"} 2', $prom);
        self::assertStringContainsString('kongono_active_workers 4', $prom);
        self::assertStringContainsString('kongono_request_ms_count{route="home"} 1', $prom);

        $tracer = new Tracer();
        $val = $tracer->span('db_query', static fn(): int => 123);
        self::assertSame(123, $val);
        self::assertStringContainsString('db_query;dur=', $tracer->toServerTimingHeader());
    }

    public function testTranslatorInterpolationPluralizationAndNegotiation(): void
    {
        $translator = (new Translator('en'))
            ->addMessages('en', [
                'welcome' => 'Hello, :name!',
                'items' => 'No items|One item|:count items',
                'files' => '1 file|:count files',
                'only_en' => 'English fallback',
            ])
            ->addMessages('fr', [
                'welcome' => 'Bonjour, :name !',
            ]);

        self::assertSame('Hello, Ada!', $translator->get('welcome', ['name' => 'Ada']));
        self::assertSame('Bonjour, Ada !', $translator->get('welcome', ['name' => 'Ada'], 'fr-CA'));
        self::assertSame('English fallback', $translator->get('only_en', [], 'fr'));
        self::assertSame('missing.key', $translator->get('missing.key'));

        self::assertSame('No items', $translator->choice('items', 0));
        self::assertSame('One item', $translator->choice('items', 1));
        self::assertSame('5 items', $translator->choice('items', 5));
        self::assertSame('1 file', $translator->choice('files', 1));
        self::assertSame('3 files', $translator->choice('files', 3));

        self::assertSame('fr', $translator->negotiate('de-DE, fr-CA;q=0.9, en;q=0.8'));
        self::assertSame('en', $translator->negotiate('es-MX'));
    }

    public function testHealthCheckReportsOkAndDegradedWithScrubbedErrors(): void
    {
        $healthy = (new HealthCheck())
            ->check('db', static fn(): bool => true)
            ->check('cache', static fn(): bool => true)
            ->run();

        self::assertSame('ok', $healthy['status']);
        self::assertTrue($healthy['healthy']);
        self::assertTrue($healthy['checks']['db']['ok']);

        $degradedHidden = (new HealthCheck())
            ->check('ok_probe', static fn(): bool => true)
            ->check('false_probe', static fn(): bool => false)
            ->check('crash_probe', static function (): bool {
                throw new CoreException('Failed auth password=supersecretvalue at 10.0.0.5:6379');
            })
            ->run();

        self::assertSame('degraded', $degradedHidden['status']);
        self::assertFalse($degradedHidden['healthy']);
        self::assertFalse($degradedHidden['checks']['false_probe']['ok']);
        self::assertFalse($degradedHidden['checks']['crash_probe']['ok']);
        self::assertSame('Health check failed.', $degradedHidden['checks']['crash_probe']['error'] ?? null);

        $degraded = (new HealthCheck(exposeErrors: true))
            ->check('crash_probe', static function (): bool {
                throw new CoreException('Failed auth password=supersecretvalue');
            })
            ->run();

        self::assertArrayHasKey('error', $degraded['checks']['crash_probe']);
        self::assertStringNotContainsString('supersecretvalue', $degraded['checks']['crash_probe']['error']);
        self::assertStringContainsString('[REDACTED]', $degraded['checks']['crash_probe']['error']);
    }

    public function testRedisClientRespProtocolAndRedisCache(): void
    {
        self::assertSame("*2\r\n\$3\r\nGET\r\n\$3\r\nfoo\r\n", RedisClient::encodeCommand('GET', 'foo'));

        $domain = '\\' === DIRECTORY_SEPARATOR ? STREAM_PF_INET : STREAM_PF_UNIX;
        $pair = stream_socket_pair($domain, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        self::assertIsArray($pair);
        [$clientSock, $serverSock] = $pair;

        // Preload deterministic RESP2/RESP3 replies onto the peer socket buffer
        $payload = json_encode(['name' => 'Kongono'], JSON_THROW_ON_ERROR);
        fwrite(
            $serverSock,
            "+PONG\r\n"
            . "+OK\r\n"
            . '$' . strlen($payload) . "\r\n" . $payload . "\r\n"
            . ":1\r\n"
            . "$-1\r\n"
            . "+OK\r\n"
            . "*1\r\n\$16\r\nkongono:cache:k1\r\n"
            . ":1\r\n",
        );

        try {
            $redis = RedisClient::fromStream($clientSock);
            self::assertSame('PONG', $redis->ping());

            $cache = new RedisCache($redis);
            $cache->set('k1', ['name' => 'Kongono'], ttlSeconds: 60);
            self::assertSame(['name' => 'Kongono'], $cache->get('k1'));
            self::assertTrue($cache->has('k1'));

            // remember() miss computes & stores value
            $computed = $cache->remember('k2', 60, static fn(): string => 'computed');
            self::assertSame('computed', $computed);

            // clear() only deletes prefixed keys
            $cache->clear();
            $redis->close();
        } finally {
            fclose($serverSock);
        }
    }

    public function testFeatureManagerRolloutsOverridesAndNotificationsDispatcher(): void
    {
        $cache = new MemoryCache();
        $features = (new FeatureManager($cache))
            ->define('ai_tutor', static fn(?string $scope): bool => 'pro' === $scope)
            ->rollout('new_checkout', 50);

        self::assertTrue($features->active('ai_tutor', 'pro'));
        self::assertFalse($features->active('ai_tutor', 'free'));
        self::assertFalse($features->active('unknown_flag'));

        // Scoped override beats resolver; deterministic rollout repeats identically
        $features->enable('ai_tutor', 'free');
        self::assertTrue($features->active('ai_tutor', 'free'));
        $first = $features->active('new_checkout', 'user-42');
        self::assertSame($first, $features->active('new_checkout', 'user-42'));
        self::assertArrayHasKey('ai_tutor', $features->all('pro'));

        // Multi-channel NotificationDispatcher isolates failing channels and scrubs secrets
        $memoryChannel = new MemoryNotificationChannel('in_app');
        $failingChannel = new class implements NotificationChannelInterface {
            public function name(): string
            {
                return 'sms';
            }

            public function send(array $recipient, Notification $notification): void
            {
                throw new CoreException('SMS provider error token=secret_abc123');
            }
        };

        $dispatcher = (new NotificationDispatcher())
            ->registerChannel($memoryChannel)
            ->registerChannel($failingChannel);

        $results = $dispatcher->send(
            ['user_id' => 'u-1'],
            new Notification('invoice.paid', 'Paid!', 'Your invoice was paid.'),
            ['in_app', 'sms', 'missing'],
        );

        self::assertTrue($results['in_app']['ok']);
        self::assertCount(1, $memoryChannel->sent());
        self::assertFalse($results['sms']['ok']);
        self::assertStringNotContainsString('secret_abc123', $results['sms']['error'] ?? '');
        self::assertStringContainsString('[REDACTED]', $results['sms']['error'] ?? '');
        self::assertFalse($results['missing']['ok']);
    }

    public function testRetryExponentialBackoffAndCircuitBreakerLifecycle(): void
    {
        $delays = [];
        $result = Retry::run(
            static function (int $attempt): string {
                if ($attempt < 3) {
                    throw new CoreException('Transient timeout');
                }

                return 'recovered';
            },
            maxAttempts: 4,
            baseDelayMs: 10,
            sleeper: static function (int $ms) use (&$delays): void {
                $delays[] = $ms;
            },
        );

        self::assertSame('recovered', $result);
        self::assertSame([10, 20], $delays);

        // CircuitBreaker Closed -> Open -> fails fast -> HalfOpen -> Closed
        $cb = new CircuitBreaker('stripe-api', failureThreshold: 2, recoveryTimeoutSeconds: 30);
        self::assertSame(CircuitState::Closed, $cb->state(1000));

        for ($i = 0; $i < 2; ++$i) {
            try {
                $cb->call(static function (): never {
                    throw new CoreException('Upstream 503');
                }, now: 1000 + $i);
            } catch (CoreException) {
                // Expected failure
            }
        }
        self::assertSame(CircuitState::Open, $cb->state(1010));

        // Open circuit fails fast without invoking callback
        $invoked = false;
        try {
            $cb->call(static function () use (&$invoked): string {
                $invoked = true;

                return 'should-not-run';
            }, now: 1015);
            self::fail('Expected open circuit to fail fast.');
        } catch (CoreException $e) {
            self::assertFalse($invoked);
            self::assertStringContainsString('OPEN', $e->getMessage());
        }

        // After recovery cooldown elapses, HalfOpen probe succeeds and closes circuit
        self::assertSame(CircuitState::HalfOpen, $cb->state(1035));
        $recovered = $cb->call(static fn(): string => 'ok', now: 1035);
        self::assertSame('ok', $recovered);
        self::assertSame(CircuitState::Closed, $cb->state(1035));
        self::assertSame(0, $cb->consecutiveFailures());
    }

    public function testAsyncFibersAllRaceMapAndAllSettled(): void
    {
        // Cooperative interleaving across Fibers preserves key order
        $trace = [];
        $results = Async::all([
            'first' => static function () use (&$trace): string {
                $trace[] = 'a1';
                Async::suspend();
                $trace[] = 'a2';

                return 'A';
            },
            'second' => static function () use (&$trace): string {
                $trace[] = 'b1';
                Async::suspend();
                $trace[] = 'b2';

                return 'B';
            },
        ]);

        self::assertSame(['first' => 'A', 'second' => 'B'], $results);
        self::assertSame(['a1', 'b1', 'a2', 'b2'], $trace);

        // Async::race resolves to whichever Fiber finishes first
        $winner = Async::race([
            'slow' => static function (): string {
                Async::suspend();
                Async::suspend();

                return 'slow';
            },
            'fast' => static function (): string {
                Async::suspend();

                return 'fast';
            },
        ]);
        self::assertSame('fast', $winner);

        // Async::map transforms items concurrently preserving keys
        $doubled = Async::map(['x' => 3, 'y' => 7], static function (int $v): int {
            Async::suspend();

            return $v * 2;
        });
        self::assertSame(['x' => 6, 'y' => 14], $doubled);

        // Async::allSettled isolates exceptions without aborting siblings
        $settled = Async::allSettled([
            'ok' => static fn(): int => 42,
            'boom' => static function (): int {
                throw new CoreException('isolated');
            },
        ]);
        self::assertTrue($settled['ok']['ok']);
        self::assertSame(42, $settled['ok']['value']);
        self::assertFalse($settled['boom']['ok']);
        self::assertSame('isolated', $settled['boom']['error']->getMessage());

        // Calling Async::suspend() outside a Fiber is a safe no-op
        self::assertSame('pass', Async::suspend('pass'));
    }

    public function testRedisClientRejectsOversizedRespBulkStringDos(): void
    {
        $domain = '\\' === DIRECTORY_SEPARATOR ? STREAM_PF_INET : STREAM_PF_UNIX;
        $pair = stream_socket_pair($domain, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        self::assertIsArray($pair);
        [$serverSock, $clientSock] = $pair;
        fwrite($serverSock, "$999999999\r\n");

        try {
            $redis = RedisClient::fromStream($clientSock);
            $this->expectException(CoreException::class);
            $this->expectExceptionMessage('exceeds maximum bound');
            $redis->get('boom');
        } finally {
            if (is_resource($serverSock)) {
                fclose($serverSock);
            }
            if (is_resource($clientSock)) {
                fclose($clientSock);
            }
        }
    }

    public function testRound3SecretScrubberLoggerAtomicCacheFeaturesAndEnvLoaderHardening(): void
    {
        // 1. SecretScrubber: JSON-quoted, Basic auth, Cookie, APP_KEY, Resend, truncated PEM, camelCase, Throwable
        $raw = 'Authorization: Basic dXNlcjpwYXNz | Cookie: sid=abc123 | {"password":"s3cr3t","apiKey":"re_9999999999999999"} | APP_KEY=base64:abcdef123456 | -----BEGIN PRIVATE KEY-----MIIEvQIBADAN';
        $scrubbed = SecretScrubber::scrub($raw);
        self::assertStringNotContainsString('dXNlcjpwYXNz', $scrubbed);
        self::assertStringNotContainsString('sid=abc123', $scrubbed);
        self::assertStringNotContainsString('s3cr3t', $scrubbed);
        self::assertStringNotContainsString('re_9999999999999999', $scrubbed);
        self::assertStringNotContainsString('base64:abcdef123456', $scrubbed);
        self::assertStringNotContainsString('MIIEvQIBADAN', $scrubbed);

        $scrubbedArr = SecretScrubber::scrubArray([
            'clientSecret' => 'top-secret',
            'nestedErr' => new CoreException('Bearer super_secret_tok_999'),
        ]);
        self::assertSame('[REDACTED]', $scrubbedArr['clientSecret']);
        self::assertIsString($scrubbedArr['nestedErr']);
        self::assertStringNotContainsString('super_secret_tok_999', $scrubbedArr['nestedErr']);

        // Diagnostic::toSafeArray() scrubs title and remediation too
        $diag = new Diagnostic('KGN-TEST', 'Failed with token=abc_secret_xyz', 'Use password=my_pass_123');
        $safe = $diag->toSafeArray();
        self::assertStringNotContainsString('abc_secret_xyz', $safe['title']);
        self::assertStringNotContainsString('my_pass_123', $safe['remediation']);

        // 2. Logger: redacts {password} BEFORE interpolation AND survives invalid UTF-8 bytes
        $logBuffer = fopen('php://memory', 'r+b');
        self::assertIsResource($logBuffer);
        try {
            $logger = new Logger('sec', stream: $logBuffer, retainInMemory: true);
            $logger->warning("Auth fail for {password} with raw \xFF\xFE bytes", ['password' => 'hunter2_plain']);
            $rec = $logger->records()[0];
            self::assertStringNotContainsString('hunter2_plain', $rec['message']);
            self::assertSame('[REDACTED]', $rec['context']['password']);
            rewind($logBuffer);
            $jsonLine = (string) stream_get_contents($logBuffer);
            self::assertNotSame('', trim($jsonLine));
            self::assertStringNotContainsString('hunter2_plain', $jsonLine);
        } finally {
            fclose($logBuffer);
        }

        // 3. HealthCheck defaults to nondisclosing generic error text
        $health = (new HealthCheck())->check('db', static function (): bool {
            throw new CoreException('SQLSTATE[08006]: could not connect to 10.0.0.42:5432');
        });
        $report = $health->run();
        self::assertSame('degraded', $report['status']);
        self::assertSame('Health check failed.', $report['checks']['db']['error'] ?? '');
        self::assertStringNotContainsString('10.0.0.42', $report['checks']['db']['error'] ?? '');

        // 4. AtomicCacheInterface on MemoryCache & FileCache (add, increment, pull)
        $mem = new MemoryCache();
        self::assertTrue($mem->add('lock:1', 'owner-a', 60));
        self::assertFalse($mem->add('lock:1', 'owner-b', 60));
        self::assertSame(1, $mem->increment('rate:1', 1, 60));
        self::assertSame(2, $mem->increment('rate:1', 1, 60));
        self::assertSame('owner-a', $mem->pull('lock:1'));
        self::assertNull($mem->pull('lock:1'));

        $cacheDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kongono-fcache-r3-' . bin2hex(random_bytes(5));
        try {
            $fc = new FileCache($cacheDir);
            self::assertTrue($fc->add('once', 'tok-1', 60));
            self::assertFalse($fc->add('once', 'tok-2', 60));
            self::assertSame(1, $fc->increment('hits', 1, 60));
            self::assertSame(3, $fc->increment('hits', 2, 60));
            self::assertSame('tok-1', $fc->pull('once'));
            self::assertNull($fc->pull('once'));
        } finally {
            foreach (glob($cacheDir . DIRECTORY_SEPARATOR . '*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($cacheDir);
        }

        // 5. FeatureManager prevents `__global__` scope key collision
        $fm = new FeatureManager();
        $fm->define('beta', static fn(): bool => false);
        $fm->enable('beta', '__global__');
        self::assertFalse($fm->active('beta'));
        self::assertTrue($fm->active('beta', '__global__'));

        // 6. EnvLoader blocks dangerous SAPI/OS variables (REMOTE_ADDR, HTTP_HOST, LD_PRELOAD)
        $envFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kongono-env-r3-' . bin2hex(random_bytes(5)) . '.env';
        file_put_contents($envFile, "SAFE_R3_FLAG=ok\nREMOTE_ADDR=127.0.0.1\nHTTP_HOST=evil.test\nLD_PRELOAD=/tmp/pwn.so\n");
        try {
            $loaded = EnvLoader::load($envFile, overwrite: true);
            self::assertSame(['SAFE_R3_FLAG' => 'ok'], $loaded);
            self::assertArrayNotHasKey('REMOTE_ADDR', $loaded);
            self::assertArrayNotHasKey('HTTP_HOST', $loaded);
            self::assertArrayNotHasKey('LD_PRELOAD', $loaded);
        } finally {
            unset($_ENV['SAFE_R3_FLAG'], $_SERVER['SAFE_R3_FLAG']);
            @unlink($envFile);
        }
    }
}
