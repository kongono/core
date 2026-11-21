<?php

declare(strict_types=1);

namespace Kongono\Core\Tests;

use Kongono\Core\Cache\FileCache;
use Kongono\Core\Cache\MemoryCache;
use Kongono\Core\Config;
use Kongono\Core\Container;
use Kongono\Core\ContainerException;
use Kongono\Core\CoreException;
use Kongono\Core\Diagnostics\Diagnostic;
use Kongono\Core\Diagnostics\Disclosure;
use Kongono\Core\Diagnostics\SecretScrubber;
use Kongono\Core\EnvLoader;
use Kongono\Core\Events\EventDispatcher;
use Kongono\Core\Graph\ApplicationGraph;
use Kongono\Core\Graph\RouteNode;
use Kongono\Core\Graph\ServiceNode;
use Kongono\Core\Health\HealthCheck;
use Kongono\Core\I18n\Translator;
use Kongono\Core\Kernel;
use Kongono\Core\KernelState;
use Kongono\Core\Log\Logger;
use Kongono\Core\OperationScope;
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

        $degraded = (new HealthCheck())
            ->check('ok_probe', static fn(): bool => true)
            ->check('false_probe', static fn(): bool => false)
            ->check('crash_probe', static function (): bool {
                throw new CoreException('Failed auth password=supersecretvalue');
            })
            ->run();

        self::assertSame('degraded', $degraded['status']);
        self::assertFalse($degraded['healthy']);
        self::assertFalse($degraded['checks']['false_probe']['ok']);
        self::assertFalse($degraded['checks']['crash_probe']['ok']);
        self::assertArrayHasKey('error', $degraded['checks']['crash_probe']);
        self::assertStringNotContainsString('supersecretvalue', $degraded['checks']['crash_probe']['error']);
        self::assertStringContainsString('[REDACTED]', $degraded['checks']['crash_probe']['error']);
    }
}
