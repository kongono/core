<?php

declare(strict_types=1);

namespace Kongono\Core\Tests;

use Error;
use Kongono\Core\Diagnostics\ErrorExplainer;
use Kongono\Core\Log\Logger;
use Kongono\Http\App;
use Kongono\Http\HttpException;
use Kongono\Http\Request;
use Kongono\Security\Middleware\SecurityHeadersMiddleware;
use Kongono\View\ViewEngine;
use ParseError;
use PDOException;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use RuntimeException;
use TypeError;

final class ErrorExplainerTest extends TestCase
{
    public function testReflectionSuggestsClosestMethodOnTypo(): void
    {
        $explainer = new ErrorExplainer();
        $err = new Error('Call to undefined method Kongono\\Core\\Diagnostics\\ErrorExplainer::explainThrowble()');

        $exp = $explainer->explainThrowable($err, method: 'GET', path: '/orders');
        self::assertSame('KGN-ERR-UNDEFINED-METHOD', $exp->code);
        self::assertContains('ErrorExplainer::explainThrowable()', $exp->didYouMean);
        self::assertStringContainsString('explainThrowable', $exp->why);
        self::assertStringContainsString('explainThrowable', (string) $exp->codeFix);
    }

    public function testCompiledViewSourceMapResolvesTemplateFile(): void
    {
        $tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kgn-vmap-' . bin2hex(random_bytes(4));
        $viewsDir = $tmpDir . DIRECTORY_SEPARATOR . 'views';
        $cacheDir = $tmpDir . DIRECTORY_SEPARATOR . 'cache';
        mkdir($viewsDir . DIRECTORY_SEPARATOR . 'pages', 0o775, true);
        mkdir($cacheDir, 0o775, true);

        try {
            file_put_contents($viewsDir . DIRECTORY_SEPARATOR . 'pages' . DIRECTORY_SEPARATOR . 'invoice.kgn.html', '<h1>{{ $title }}</h1>');
            $engine = new ViewEngine($viewsDir, $cacheDir);
            self::assertSame('<h1>Paid</h1>', $engine->render('pages/invoice', ['title' => 'Paid']));

            $compiledFiles = glob($cacheDir . DIRECTORY_SEPARATOR . '*.php');
            self::assertIsArray($compiledFiles);
            self::assertCount(1, $compiledFiles);

            $explainer = new ErrorExplainer();
            $mapped = $explainer->resolveCompiledViewSource($compiledFiles[0]);
            self::assertNotNull($mapped);
            self::assertSame('pages/invoice', $mapped['template_name']);
            self::assertSame('views/pages/invoice.kgn.html', $mapped['template_path']);
        } finally {
            foreach (glob($cacheDir . DIRECTORY_SEPARATOR . '*') ?: [] as $f) {
                @unlink($f);
            }
            @unlink($viewsDir . DIRECTORY_SEPARATOR . 'pages' . DIRECTORY_SEPARATOR . 'invoice.kgn.html');
            @rmdir($viewsDir . DIRECTORY_SEPARATOR . 'pages');
            @rmdir($viewsDir);
            @rmdir($cacheDir);
            @rmdir($tmpDir);
        }
    }

    public function testExplainsZokeibiComponentDbTypeAndSecretsSafely(): void
    {
        $explainer = new ErrorExplainer();

        $zokeibiExp = $explainer->explainThrowable(new RuntimeException('Template "components/ui/popover" not found.'));
        self::assertSame('KGN-ERR-ZOKEIBI-COMPONENT-MISSING', $zokeibiExp->code);
        self::assertStringContainsString('zokeibi add popover', (string) $zokeibiExp->command);

        $dbExp = $explainer->explainThrowable(new PDOException('SQLSTATE[42P01]: Undefined table: relation "invoices" does not exist'));
        self::assertSame('KGN-ERR-DB-NO-TABLE', $dbExp->code);
        self::assertStringContainsString('migrate', (string) $dbExp->command);

        $typeExp = $explainer->explainThrowable(new TypeError('OrderController::show(): Argument #1 ($id) must be of type int, string given'));
        self::assertSame('KGN-ERR-TYPE-MISMATCH', $typeExp->code);
        self::assertStringContainsString('$id', $typeExp->what);
        self::assertStringContainsString('int', $typeExp->what);

        $parseExp = $explainer->explainThrowable(new ParseError('syntax error, unexpected token ";"'));
        self::assertSame('KGN-ERR-PHP-SYNTAX', $parseExp->code);

        // Secret scrubbing across 5W1H array & Markdown
        $dummyKey = 'sk_' . 'live_supersecretkey999999999';
        $secretExp = $explainer->explainThrowable(new RuntimeException('Failed with bearer ' . $dummyKey));
        $arr = $secretExp->toArray();
        self::assertStringNotContainsString($dummyKey, $arr['what']);
        self::assertStringNotContainsString($dummyKey, $secretExp->toMarkdown());
    }

    public function testExplainsHttp404Typo404MethodMismatchAnd403Csrf(): void
    {
        $explainer = new ErrorExplainer();
        $routes = ['GET /dashboard', 'POST /billing', 'GET /studio'];

        $typo404 = $explainer->explainHttpStatus(404, 'Not Found', 'GET', '/dashbord', $routes);
        self::assertSame('KGN-HTTP-404-ROUTE-NOT-FOUND', $typo404->code);
        self::assertContains('GET /dashboard', $typo404->didYouMean);

        $method404 = $explainer->explainHttpStatus(404, 'Not Found', 'GET', '/billing', $routes);
        self::assertSame('KGN-HTTP-404-METHOD-MISMATCH', $method404->code);
        self::assertContains('POST /billing', $method404->didYouMean);

        $csrf403 = $explainer->explainHttpStatus(403, 'Invalid or missing CSRF token.', 'POST', '/studio/save', $routes);
        self::assertSame('KGN-HTTP-403-CSRF', $csrf403->code);
        self::assertStringContainsString('_csrf', implode(' ', $csrf403->howToFix));
        self::assertStringContainsString('_csrf', (string) $csrf403->codeFix);
    }

    public function testDebugVsProductionDisclosureOnHttpErrors(): void
    {
        $tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kgn-app-exp-' . bin2hex(random_bytes(4));
        mkdir($tmpDir, 0o775, true);

        try {
            $devApp = App::create($tmpDir, name: 'DevTest')->debug(true);
            $devApp->router()->get('/dashboard', static fn(): string => 'ok');

            // Dev JSON 404 includes structured 5W1H explanation with "Did you mean"
            $devJson = $devApp->handle(Request::create('GET', '/dashbord', headers: ['Accept' => 'application/json']));
            self::assertSame(404, $devJson->getStatusCode());
            $decoded = json_decode((string) $devJson->getBody(), true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($decoded);
            self::assertIsArray($decoded['explanation']);
            self::assertSame('KGN-HTTP-404-ROUTE-NOT-FOUND', $decoded['explanation']['code']);
            self::assertIsArray($decoded['explanation']['did_you_mean']);
            self::assertContains('GET /dashboard', $decoded['explanation']['did_you_mean']);

            // Dev HTML 404 includes Plain-English Diagnosis card
            $devHtml = $devApp->handle(Request::create('GET', '/dashbord'));
            self::assertSame(404, $devHtml->getStatusCode());
            self::assertStringContainsString('Plain-English Diagnosis', (string) $devHtml->getBody());
            self::assertStringContainsString('GET /dashboard', (string) $devHtml->getBody());

            // Production (debug=false) NEVER leaks route suggestions or internal explanation
            $prodApp = App::create($tmpDir, name: 'ProdTest')->debug(false);
            $prodApp->router()->get('/dashboard', static fn(): string => 'ok');
            $prodJson = $prodApp->handle(Request::create('GET', '/dashbord', headers: ['Accept' => 'application/json']));
            self::assertSame(404, $prodJson->getStatusCode());
            $prodDecoded = json_decode((string) $prodJson->getBody(), true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($prodDecoded);
            self::assertArrayNotHasKey('explanation', $prodDecoded);
            self::assertArrayNotHasKey('execution_trace', $prodDecoded);
            self::assertIsString($prodDecoded['reference'] ?? null);
            self::assertMatchesRegularExpression('/^KGN-\d{8}-[A-F0-9]{8}$/', $prodDecoded['reference']);
        } finally {
            @rmdir($tmpDir);
        }
    }

    public function testDevModeShowsXRayExecutionTraceInlineCodeAndIdeLink(): void
    {
        $tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kgn-xray-' . bin2hex(random_bytes(4));
        mkdir($tmpDir, 0o775, true);

        try {
            $app = App::create($tmpDir, name: 'DevXRay')
                ->debug(true)
                ->middleware(new SecurityHeadersMiddleware());
            $app->router()->get('/orders/{id}', static function (): never {
                throw new Error('Call to undefined method Kongono\\Core\\Diagnostics\\ErrorExplainer::explainThrowble()');
            });

            $htmlRes = $app->handle(Request::create('GET', '/orders/42?tab=items', query: ['tab' => 'items']));
            self::assertSame(500, $htmlRes->getStatusCode());
            self::assertMatchesRegularExpression('/^KGN-\d{8}-[A-F0-9]{8}$/', $htmlRes->getHeaderLine('X-Kongono-Error-Id'));
            self::assertSame('no-store', $htmlRes->getHeaderLine('Cache-Control'));

            $html = (string) $htmlRes->getBody();
            self::assertStringContainsString('Execution Trace', $html);
            self::assertStringContainsString('SecurityHeadersMiddleware', $html);
            self::assertStringContainsString('GET /orders/{id}', $html);
            self::assertStringContainsString('class="w5-inline"', $html);
            self::assertStringContainsString('Open in VS Code', $html);
            self::assertStringContainsString('vscode://file/', $html);
            self::assertStringContainsString('Copy code fix', $html);

            $jsonRes = $app->handle(Request::create('GET', '/orders/42?tab=items', headers: ['Accept' => 'application/json'], query: ['tab' => 'items']));
            self::assertSame(500, $jsonRes->getStatusCode());
            $data = json_decode((string) $jsonRes->getBody(), true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($data);
            self::assertIsArray($data['execution_trace']);
            self::assertSame('GET /orders/{id}', $data['execution_trace']['matched_route']);
            self::assertSame(['SecurityHeadersMiddleware'], $data['execution_trace']['middleware']);
            self::assertSame(['id' => '42'], $data['execution_trace']['route_params']);
            self::assertSame(['tab'], $data['execution_trace']['query_keys']);
        } finally {
            @rmdir($tmpDir);
        }
    }

    public function testProductionModeIsStrictlyVagueNondisclosingAndLogsCorrelated5W1H(): void
    {
        $tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kgn-prod-noleak-' . bin2hex(random_bytes(4));
        mkdir($tmpDir, 0o775, true);

        try {
            $logger = new Logger('prod-test', retainInMemory: true);
            $app = App::create($tmpDir, name: 'BankProd')
                ->debug(false)
                ->instance(LoggerInterface::class, $logger);
            $app->router()->get('/accounts', static function (): never {
                throw new PDOException('SQLSTATE[42P01]: relation "secret_accounts" does not exist');
            });
            $app->router()->post('/transfer', static function (): never {
                throw new HttpException(403, 'Invalid or missing CSRF token on session cookie');
            });

            // 1. Production 500 HTML is completely vague + carries opaque Reference ID
            $html500 = $app->handle(Request::create('GET', '/accounts'));
            self::assertSame(500, $html500->getStatusCode());
            $ref500 = $html500->getHeaderLine('X-Kongono-Error-Id');
            self::assertMatchesRegularExpression('/^KGN-\d{8}-[A-F0-9]{8}$/', $ref500);
            self::assertSame('no-store', $html500->getHeaderLine('Cache-Control'));

            $body500 = (string) $html500->getBody();
            self::assertStringContainsString('An internal server error occurred.', $body500);
            self::assertStringContainsString($ref500, $body500);
            self::assertStringNotContainsString('SQLSTATE', $body500);
            self::assertStringNotContainsString('secret_accounts', $body500);
            self::assertStringNotContainsString('PDOException', $body500);
            self::assertStringNotContainsString('Plain-English Diagnosis', $body500);
            self::assertStringNotContainsString('Execution Trace', $body500);
            self::assertStringNotContainsString('vscode://', $body500);
            self::assertStringNotContainsString('<script', $body500);

            // 2. Production 500 JSON contains ONLY vague message + opaque Reference ID
            $json500 = $app->handle(Request::create('GET', '/accounts', headers: ['Accept' => 'application/json']));
            $d500 = json_decode((string) $json500->getBody(), true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($d500);
            self::assertSame('An internal server error occurred.', $d500['message']);
            self::assertArrayNotHasKey('explanation', $d500);
            self::assertArrayNotHasKey('execution_trace', $d500);
            self::assertArrayNotHasKey('diagnostic', $d500);

            // 3. Production 403 CSRF neutralizes internal "CSRF"/"session" wording to vague public message
            $res403 = $app->handle(Request::create('POST', '/transfer', headers: ['Accept' => 'application/json']));
            self::assertSame(403, $res403->getStatusCode());
            $ref403 = $res403->getHeaderLine('X-Kongono-Error-Id');
            self::assertMatchesRegularExpression('/^KGN-\d{8}-[A-F0-9]{8}$/', $ref403);
            self::assertSame('no-store', $res403->getHeaderLine('Cache-Control'));
            $d403 = json_decode((string) $res403->getBody(), true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($d403);
            self::assertIsString($d403['message']);
            self::assertStringNotContainsString('CSRF', $d403['message']);
            self::assertStringNotContainsString('session', strtolower($d403['message']));
            self::assertArrayNotHasKey('explanation', $d403);

            // 4. Server-side logger holds the complete 5W1H diagnosis indexed by exact Reference IDs!
            $records = $logger->records();
            self::assertGreaterThanOrEqual(3, count($records));
            $matched500 = null;
            $matched403 = null;
            foreach ($records as $rec) {
                if (($rec['context']['reference'] ?? null) === $ref500) {
                    $matched500 = $rec;
                }
                if (($rec['context']['reference'] ?? null) === $ref403) {
                    $matched403 = $rec;
                }
            }
            self::assertNotNull($matched500);
            self::assertSame('KGN-ERR-DB-NO-TABLE', $matched500['context']['code']);
            self::assertNotNull($matched403);
            self::assertSame('KGN-HTTP-403-CSRF', $matched403['context']['code']);
        } finally {
            @rmdir($tmpDir);
        }
    }
}
