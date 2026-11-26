<?php

declare(strict_types=1);

namespace Kongono\Core\Tests;

use Kongono\Core\Env\EnvExampleGenerator;
use Kongono\Core\Graph\ApplicationGraph;
use Kongono\Core\Graph\ServiceNode;
use PHPUnit\Framework\TestCase;

final class EnvExampleGeneratorTest extends TestCase
{
    public function testDetectsIntegrationsCustomKeysAndNeverLeaksSecrets(): void
    {
        $tmp = $this->makeTempDir('env-gen-');
        $fakeStripeProc = 'sk_' . 'test_' . '51SuperSecretProcessEnvValue123456';
        $fakeStripeEnv = 'sk_' . 'test_' . '51RealDotEnvSecretValue9876543210';
        $fakeStripeFallback = 'sk_' . 'test_' . '51HardcodedFallbackMustBeBlankedOut';
        $fakeGhToken = 'ghp' . '_1234567890abcdefghij1234567890abcd';
        $fakeWhsec = 'whsec' . '_1234567890abcdef1234567890';
        $fakeJwt = 'eyJhbGci' . 'OiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.REAL_SIGNATURE_1234';
        $prevStripe = $_ENV['STRIPE_SECRET_KEY'] ?? null;
        $_ENV['STRIPE_SECRET_KEY'] = $fakeStripeProc;

        try {
            mkdir($tmp . '/app', 0o775, true);
            mkdir($tmp . '/src/Billing', 0o775, true);

            // Real .env full of sensitive credentials that MUST NEVER be read or copied
            file_put_contents($tmp . '/.env', implode("\n", [
                'APP_KEY=base64:REAL_PRODUCTION_KEY_DO_NOT_COPY_1234567890',
                'STRIPE_SECRET_KEY=' . $fakeStripeEnv,
                'SUPABASE_SERVICE_ROLE_KEY=' . $fakeJwt,
                'DATABASE_URL=pgsql://admin:TopSecretDbPass@db.internal:5432/prod',
                'ACME_API_TOKEN=' . $fakeGhToken,
            ]) . "\n");

            file_put_contents($tmp . '/composer.json', json_encode([
                'name' => 'acme/saas-billing',
                'require' => [
                    'php' => '>=8.5.13',
                    'kongono/framework' => '^1.20',
                    'stripe/stripe-php' => '^16.0',
                    'resend/resend-php' => '^0.15',
                    'sentry/sentry' => '^4.0',
                ],
            ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));

            file_put_contents($tmp . '/src/Billing/CheckoutService.php', str_replace(
                ['__STRIPE_FALLBACK__', '__WHSEC_FALLBACK__'],
                [$fakeStripeFallback, $fakeWhsec],
                <<<'PHP'
<?php
declare(strict_types=1);
namespace App\Billing;

use Kongono\Core\Config;

final class CheckoutService
{
    public function boot(): array
    {
        $stripe = Config::env('STRIPE_SECRET_KEY', '__STRIPE_FALLBACK__');
        $supabaseUrl = Config::env('SUPABASE_URL');
        $customSafe = Config::env('BILLING_CURRENCY', 'USD');
        $customCoalesce = Config::env('APP_TIMEZONE') ?? 'UTC';
        $customSecret = getenv('ACME_API_TOKEN');
        $envFallbackSecret = $_ENV['WEBHOOK_FALLBACK'] ?? '__WHSEC_FALLBACK__';
        // Standard CGI $_SERVER keys must be ignored
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $remote = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        return [$stripe, $supabaseUrl, $customSafe, $customCoalesce, $customSecret, $envFallbackSecret, $method, $auth, $remote];
    }
}
PHP,
            ));

            $graph = new ApplicationGraph(
                appName: 'Acme SaaS',
                basePath: $tmp,
                services: [
                    new ServiceNode('Kongono\\Database\\ConnectionInterface', 'singleton'),
                    new ServiceNode('Kongono\\Core\\Cache\\RedisCache', 'singleton'),
                    new ServiceNode('Kongono\\Storage\\S3Storage', 'singleton'),
                ],
                middleware: [
                    'Kongono\\Http\\Session\\SessionMiddleware',
                ],
            );

            $generator = new EnvExampleGenerator();
            $report = $generator->sync($tmp, $graph, write: true);

            self::assertTrue($report['wrote']);
            self::assertTrue($report['in_sync']);
            self::assertFileExists($tmp . '/.env.example');

            self::assertContains('Stripe', $report['detected_integrations']);
            self::assertContains('Supabase', $report['detected_integrations']);
            self::assertContains('Database', $report['detected_integrations']);
            self::assertContains('Redis', $report['detected_integrations']);
            self::assertContains('S3 / R2 Storage', $report['detected_integrations']);
            self::assertContains('Resend', $report['detected_integrations']);
            self::assertContains('Sentry', $report['detected_integrations']);
            self::assertContains('AI Companions', $report['detected_integrations']);

            $content = (string) file_get_contents($tmp . '/.env.example');

            // Required baseline & integrations populated with safe placeholders
            self::assertStringContainsString("APP_ENV=local\n", $content);
            self::assertStringContainsString("APP_DEBUG=false\n", $content);
            self::assertStringContainsString("APP_KEY=REPLACE_WITH_kongo_key_generate\n", $content);
            self::assertStringContainsString("SESSION_SECURE=false\n", $content);
            self::assertStringContainsString("STRIPE_SECRET_KEY=\n", $content);
            self::assertStringContainsString("STRIPE_PUBLISHABLE_KEY=\n", $content);
            self::assertStringContainsString("STRIPE_WEBHOOK_SECRET=\n", $content);
            self::assertStringContainsString("SUPABASE_URL=https://your-project.supabase.co\n", $content);
            self::assertStringContainsString("SUPABASE_ANON_KEY=\n", $content);
            self::assertStringContainsString("SUPABASE_SERVICE_ROLE_KEY=\n", $content);
            self::assertStringContainsString("DATABASE_URL=sqlite://var/app.sqlite\n", $content);
            self::assertStringContainsString("REDIS_URL=redis://127.0.0.1:6379/0\n", $content);
            self::assertStringContainsString("S3_BUCKET=\n", $content);
            self::assertStringContainsString("S3_REGION=us-east-1\n", $content);
            self::assertStringContainsString("RESEND_API_KEY=\n", $content);
            self::assertStringContainsString("SENTRY_DSN=\n", $content);
            self::assertStringContainsString("BILLING_CURRENCY=USD\n", $content);
            self::assertStringContainsString("APP_TIMEZONE=UTC\n", $content);
            self::assertStringContainsString("ACME_API_TOKEN=\n", $content);
            self::assertStringContainsString("WEBHOOK_FALLBACK=\n", $content);

            // Standard CGI/HTTP $_SERVER keys MUST NOT be emitted
            self::assertStringNotContainsString('REQUEST_METHOD', $content);
            self::assertStringNotContainsString('HTTP_AUTHORIZATION', $content);
            self::assertStringNotContainsString('REMOTE_ADDR', $content);

            // ZERO sensitive data from .env, $_ENV, or hardcoded fallback secrets may leak!
            self::assertStringNotContainsString('REAL_PRODUCTION_KEY', $content);
            self::assertStringNotContainsString('sk_' . 'test_', $content);
            self::assertStringNotContainsString($fakeJwt, $content);
            self::assertStringNotContainsString('TopSecretDbPass', $content);
            self::assertStringNotContainsString($fakeGhToken, $content);
            self::assertStringNotContainsString($fakeWhsec, $content);
        } finally {
            if (null === $prevStripe) {
                unset($_ENV['STRIPE_SECRET_KEY']);
            } else {
                $_ENV['STRIPE_SECRET_KEY'] = $prevStripe;
            }
            $this->removeDir($tmp);
        }
    }

    public function testNonDestructiveMergeWhenAddingNewIntegrationsLaterAndOptionalPrune(): void
    {
        $tmp = $this->makeTempDir('env-merge-');
        try {
            mkdir($tmp . '/src', 0o775, true);
            file_put_contents($tmp . '/.env.example', "# Team custom header comment\nAPP_ENV=local\nAPP_DEBUG=false\nAPP_KEY=REPLACE_WITH_kongo_key_generate\nLEGACY_UNUSED_FLAG=on\n");

            $generator = new EnvExampleGenerator();
            $initial = $generator->analyze($tmp);
            self::assertTrue($initial['in_sync']);
            self::assertSame(['LEGACY_UNUSED_FLAG'], $initial['stale_keys']);

            // Later, developer adds Supabase + a custom env var in code
            file_put_contents($tmp . '/src/AuthClient.php', <<<'PHP'
<?php
declare(strict_types=1);
namespace App;
use Kongono\Core\Config;
final class AuthClient {
    public function url(): string {
        return (Config::env('SUPABASE_URL') ?? '') . (Config::env('FEATURE_TIER', 'pro') ?? 'pro');
    }
}
PHP);

            $drifted = $generator->analyze($tmp);
            self::assertFalse($drifted['in_sync']);
            self::assertContains('SUPABASE_URL', $drifted['missing_keys']);
            self::assertContains('SUPABASE_ANON_KEY', $drifted['missing_keys']);
            self::assertContains('SUPABASE_SERVICE_ROLE_KEY', $drifted['missing_keys']);
            self::assertContains('FEATURE_TIER', $drifted['missing_keys']);

            // Merge without pruning preserves existing header, lines, and LEGACY_UNUSED_FLAG
            $merged = $generator->sync($tmp, write: true, prune: false);
            self::assertTrue($merged['wrote']);
            self::assertTrue($merged['in_sync']);
            $afterMerge = (string) file_get_contents($tmp . '/.env.example');
            self::assertStringContainsString('# Team custom header comment', $afterMerge);
            self::assertStringContainsString('LEGACY_UNUSED_FLAG=on', $afterMerge);
            self::assertStringContainsString('SUPABASE_URL=https://your-project.supabase.co', $afterMerge);
            self::assertStringContainsString('FEATURE_TIER=pro', $afterMerge);

            // Re-running sync is 100% idempotent
            $second = $generator->sync($tmp, write: true, prune: false);
            self::assertFalse($second['changed']);
            self::assertFalse($second['wrote']);
            self::assertTrue($second['in_sync']);

            // Explicit prune removes stale key while keeping active keys
            $pruned = $generator->sync($tmp, write: true, prune: true);
            self::assertTrue($pruned['wrote']);
            self::assertSame(['LEGACY_UNUSED_FLAG'], $pruned['pruned_keys']);
            $afterPrune = (string) file_get_contents($tmp . '/.env.example');
            self::assertStringNotContainsString('LEGACY_UNUSED_FLAG', $afterPrune);
            self::assertStringContainsString('SUPABASE_URL=https://your-project.supabase.co', $afterPrune);
        } finally {
            $this->removeDir($tmp);
        }
    }

    private function makeTempDir(string $prefix): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'kongono-' . $prefix . bin2hex(random_bytes(5));
        mkdir($dir, 0o775, true);

        return $dir;
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        if (false !== $items) {
            foreach ($items as $item) {
                if ('.' === $item || '..' === $item) {
                    continue;
                }
                $path = $dir . DIRECTORY_SEPARATOR . $item;
                if (is_dir($path) && !is_link($path)) {
                    $this->removeDir($path);
                } else {
                    @unlink($path);
                }
            }
        }
        @rmdir($dir);
    }
}
