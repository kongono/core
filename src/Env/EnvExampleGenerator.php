<?php

declare(strict_types=1);

namespace Kongono\Core\Env;

use FilesystemIterator;
use Kongono\Core\Diagnostics\SecretScrubber;
use Kongono\Core\Graph\ApplicationGraph;
use PhpToken;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Project-aware, strictly nondisclosing `.env.example` analyzer & generator.
 *
 * Scans PHP source tokens (`Config::env()`, `getenv()`, `$_ENV`, `$_SERVER`),
 * `composer.json` packages, and optional live `ApplicationGraph` metadata to detect
 * both well-known integrations (Stripe, Supabase, Postgres/SQLite, Redis, S3/R2,
 * Resend/Postmark/SendGrid/SMTP, Sentry, OpenTelemetry, Clerk, Auth0, Twilio, Slack,
 * AI providers) and any custom application environment keys.
 *
 * Security invariant: NEVER reads `.env`, `.env.*`, or live process environment values.
 * Every secret/credential key emits an empty or safe placeholder and passes `SecretScrubber`.
 */
final readonly class EnvExampleGenerator
{
    private const int MAX_SCAN_FILE_BYTES = 1_048_576;

    /** @var list<string> */
    private const array SCAN_DIRS = ['app', 'src', 'config', 'public'];

    /** @var list<string> */
    private const array IGNORED_DIRS = ['vendor', 'node_modules', '.git', 'var', 'storage', '.cache', 'tests'];

    /** @var list<string> */
    private const array BASELINE_KEYS = ['APP_ENV', 'APP_DEBUG', 'APP_KEY'];

    /** @var list<string> Standard SAPI/CGI/OS $_SERVER keys that must never be exported into .env.example */
    private const array IGNORED_SERVER_KEYS = [
        'ARGC',
        'ARGV',
        'COMSPEC',
        'CONTENT_LENGTH',
        'CONTENT_TYPE',
        'DOCUMENT_ROOT',
        'DOCUMENT_URI',
        'FCGI_ROLE',
        'GATEWAY_INTERFACE',
        'HOME',
        'HTTPS',
        'ORIG_PATH_INFO',
        'PATH',
        'PATH_INFO',
        'PATH_TRANSLATED',
        'PATHEXT',
        'PHP_AUTH_DIGEST',
        'PHP_AUTH_PW',
        'PHP_AUTH_USER',
        'PHP_SELF',
        'PWD',
        'QUERY_STRING',
        'REDIRECT_STATUS',
        'REMOTE_ADDR',
        'REMOTE_HOST',
        'REMOTE_PORT',
        'REMOTE_USER',
        'REQUEST_METHOD',
        'REQUEST_SCHEME',
        'REQUEST_TIME',
        'REQUEST_TIME_FLOAT',
        'REQUEST_URI',
        'SCRIPT_FILENAME',
        'SCRIPT_NAME',
        'SERVER_ADDR',
        'SERVER_ADMIN',
        'SERVER_NAME',
        'SERVER_PORT',
        'SERVER_PROTOCOL',
        'SERVER_SIGNATURE',
        'SERVER_SOFTWARE',
        'SHELL',
        'SYSTEMROOT',
        'TEMP',
        'TERM',
        'TMP',
        'TMPDIR',
        'USER',
        'WINDIR',
    ];

    /** @var list<string> */
    private const array EXTRA_SENSITIVE_SUFFIXES = [
        '_KEY',
        '_SECRET',
        '_TOKEN',
        '_PASSWORD',
        '_PASS',
        '_PASSWD',
        '_DSN',
        '_PRIVATE',
        '_CERT',
        '_PEM',
        '_SIGNATURE',
        '_WEBHOOK',
        '_AUTH',
        '_CREDENTIAL',
        '_CREDENTIALS',
        '_SALT',
        '_PEPPER',
        '_SID',
        '_APIKEY',
    ];

    /** @var list<string> */
    private const array SECTION_ORDER = [
        'Application',
        'Database',
        'Cache & Queue',
        'Storage',
        'Mail',
        'Stripe',
        'Supabase',
        'Auth & Identity',
        'Messaging',
        'Observability',
        'AI Companions',
        'Custom Application',
    ];

    /**
     * Analyze a project root without modifying any files.
     *
     * @return array{
     *     exists: bool,
     *     in_sync: bool,
     *     changed: bool,
     *     wrote: bool,
     *     path: string,
     *     detected_integrations: list<string>,
     *     detected_keys: list<array{
     *         key: string,
     *         section: string,
     *         placeholder: string,
     *         required: bool,
     *         optional_commented: bool,
     *         sensitive: bool,
     *         comment: ?string,
     *         sources: list<string>
     *     }>,
     *     missing_keys: list<string>,
     *     stale_keys: list<string>,
     *     added_keys: list<string>,
     *     pruned_keys: list<string>,
     *     content: string,
     *     diff_preview: string
     * }
     */
    public function analyze(string $appRoot, ?ApplicationGraph $graph = null, bool $prune = false): array
    {
        return $this->sync($appRoot, $graph, write: false, prune: $prune);
    }

    /**
     * Analyze and optionally create or non-destructively update `.env.example`.
     *
     * @return array{
     *     exists: bool,
     *     in_sync: bool,
     *     changed: bool,
     *     wrote: bool,
     *     path: string,
     *     detected_integrations: list<string>,
     *     detected_keys: list<array{
     *         key: string,
     *         section: string,
     *         placeholder: string,
     *         required: bool,
     *         optional_commented: bool,
     *         sensitive: bool,
     *         comment: ?string,
     *         sources: list<string>
     *     }>,
     *     missing_keys: list<string>,
     *     stale_keys: list<string>,
     *     added_keys: list<string>,
     *     pruned_keys: list<string>,
     *     content: string,
     *     diff_preview: string
     * }
     */
    public function sync(string $appRoot, ?ApplicationGraph $graph = null, bool $write = false, bool $prune = false): array
    {
        $real = realpath($appRoot);
        $root = rtrim(false !== $real ? $real : $appRoot, '\\/');
        $examplePath = $root . DIRECTORY_SEPARATOR . '.env.example';
        $exists = is_file($examplePath) && !is_link($examplePath);
        $existingRaw = $exists ? file_get_contents($examplePath) : false;
        $existingContent = is_string($existingRaw) ? $existingRaw : '';

        $packages = $this->readComposerPackages($root);
        $scan = $this->scanProjectSources($root);
        $graphSignals = $this->collectGraphSignals($graph);

        /** @var array<string, array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>}> $entries */
        $entries = [];
        /** @var list<string> $integrations */
        $integrations = [];

        // 1. Baseline Kongono Application keys (always fail-closed)
        $this->addEntry($entries, 'APP_ENV', 'Application', 'local', required: true, optionalCommented: false, source: 'kongono:baseline');
        $this->addEntry($entries, 'APP_DEBUG', 'Application', 'false', required: true, optionalCommented: false, source: 'kongono:baseline');
        $this->addEntry(
            $entries,
            'APP_KEY',
            'Application',
            'REPLACE_WITH_kongo_key_generate',
            required: true,
            optionalCommented: false,
            source: 'kongono:baseline',
            comment: 'Run `php vendor/bin/kongo key:generate` and place the generated key in your untracked .env file:',
        );

        // 2. Directly referenced env keys from PHP source tokens
        foreach ($scan['keys'] as $key => $info) {
            $section = $this->inferSectionForKey($key);
            $placeholder = self::sanitizePlaceholder($key, $info['default']);
            foreach ($info['sources'] as $src) {
                $this->addEntry($entries, $key, $section, $placeholder, required: true, optionalCommented: false, source: $src, preferExplicit: true);
            }
        }

        // 3. Integration fingerprints (composer.json + code imports/signals + ApplicationGraph + key prefixes)
        $allSignals = strtolower(implode(' ', array_merge($packages, $scan['signals'], $graphSignals, array_keys($scan['keys']))));
        $hasKeyPrefix = static function (string $prefix) use ($scan): bool {
            foreach (array_keys($scan['keys']) as $k) {
                if (str_starts_with($k, $prefix)) {
                    return true;
                }
            }

            return false;
        };

        // Session cookies
        if (
            str_contains($allSignals, 'sessionmiddleware')
            || isset($scan['keys']['SESSION_SECURE'])
        ) {
            $this->addEntry($entries, 'SESSION_SECURE', 'Application', 'false', required: true, optionalCommented: false, source: 'integration:session');
        }

        // Stripe
        if (
            in_array('stripe/stripe-php', $packages, true)
            || str_contains($allSignals, 'stripe\\')
            || $hasKeyPrefix('STRIPE_')
        ) {
            $integrations[] = 'Stripe';
            $this->addEntry($entries, 'STRIPE_SECRET_KEY', 'Stripe', '', required: true, optionalCommented: false, source: 'integration:stripe');
            $this->addEntry($entries, 'STRIPE_PUBLISHABLE_KEY', 'Stripe', '', required: true, optionalCommented: false, source: 'integration:stripe');
            $this->addEntry($entries, 'STRIPE_WEBHOOK_SECRET', 'Stripe', '', required: true, optionalCommented: false, source: 'integration:stripe');
        }

        // Supabase
        if (
            $this->hasPackageMatching($packages, 'supabase')
            || str_contains($allSignals, 'supabase')
            || $hasKeyPrefix('SUPABASE_')
        ) {
            $integrations[] = 'Supabase';
            $this->addEntry($entries, 'SUPABASE_URL', 'Supabase', 'https://your-project.supabase.co', required: true, optionalCommented: false, source: 'integration:supabase');
            $this->addEntry($entries, 'SUPABASE_ANON_KEY', 'Supabase', '', required: true, optionalCommented: false, source: 'integration:supabase');
            $this->addEntry($entries, 'SUPABASE_SERVICE_ROLE_KEY', 'Supabase', '', required: true, optionalCommented: false, source: 'integration:supabase');
        }

        // Database (PdoConnection / ConnectionInterface / DATABASE_URL)
        $usesDb = str_contains($allSignals, 'pdoconnection')
            || str_contains($allSignals, 'connectioninterface')
            || isset($scan['keys']['DATABASE_URL'])
            || $hasKeyPrefix('DB_');
        if ($usesDb) {
            $integrations[] = 'Database';
            $hasGranularDb = isset($scan['keys']['DB_HOST']) || isset($scan['keys']['DB_CONNECTION']);
            if (!$hasGranularDb || isset($scan['keys']['DATABASE_URL'])) {
                $dbDefault = str_contains($allSignals, 'pgsql') || str_contains($allSignals, 'postgres')
                    ? 'pgsql://postgres:CHANGE_ME@127.0.0.1:5432/app'
                    : 'sqlite://var/app.sqlite';
                $this->addEntry($entries, 'DATABASE_URL', 'Database', $dbDefault, required: true, optionalCommented: false, source: 'integration:database');
            }
        }

        // Redis (Cache / Queue)
        if (
            in_array('predis/predis', $packages, true)
            || str_contains($allSignals, 'rediscache')
            || str_contains($allSignals, 'redisclient')
            || str_contains($allSignals, 'redisqueuedriver')
            || isset($scan['keys']['REDIS_URL'])
            || $hasKeyPrefix('REDIS_')
        ) {
            $integrations[] = 'Redis';
            if (!isset($scan['keys']['REDIS_HOST']) || isset($scan['keys']['REDIS_URL'])) {
                $this->addEntry($entries, 'REDIS_URL', 'Cache & Queue', 'redis://127.0.0.1:6379/0', required: true, optionalCommented: false, source: 'integration:redis');
            }
        }

        // S3 / Cloudflare R2 Storage
        if (
            in_array('aws/aws-sdk-php', $packages, true)
            || in_array('league/flysystem-aws-s3-v3', $packages, true)
            || str_contains($allSignals, 's3storage')
            || $hasKeyPrefix('S3_')
        ) {
            $integrations[] = 'S3 / R2 Storage';
            $this->addEntry($entries, 'S3_BUCKET', 'Storage', '', required: true, optionalCommented: false, source: 'integration:s3');
            $this->addEntry($entries, 'S3_REGION', 'Storage', 'us-east-1', required: true, optionalCommented: false, source: 'integration:s3');
            $this->addEntry($entries, 'S3_ENDPOINT', 'Storage', '', required: true, optionalCommented: false, source: 'integration:s3');
            $this->addEntry($entries, 'S3_ACCESS_KEY_ID', 'Storage', '', required: true, optionalCommented: false, source: 'integration:s3');
            $this->addEntry($entries, 'S3_SECRET_ACCESS_KEY', 'Storage', '', required: true, optionalCommented: false, source: 'integration:s3');
        }

        // Mail providers: Resend, Postmark, SendGrid, SMTP
        if (
            in_array('resend/resend-php', $packages, true)
            || str_contains($allSignals, 'resendtransport')
            || $hasKeyPrefix('RESEND_')
        ) {
            $integrations[] = 'Resend';
            $this->addEntry($entries, 'RESEND_API_KEY', 'Mail', '', required: true, optionalCommented: false, source: 'integration:resend');
            $this->addEntry($entries, 'MAIL_FROM', 'Mail', 'noreply@example.com', required: true, optionalCommented: false, source: 'integration:resend');
        }
        if (
            in_array('wildbit/postmark-php', $packages, true)
            || str_contains($allSignals, 'postmarktransport')
            || $hasKeyPrefix('POSTMARK_')
        ) {
            $integrations[] = 'Postmark';
            $this->addEntry($entries, 'POSTMARK_TOKEN', 'Mail', '', required: true, optionalCommented: false, source: 'integration:postmark');
            $this->addEntry($entries, 'MAIL_FROM', 'Mail', 'noreply@example.com', required: true, optionalCommented: false, source: 'integration:postmark');
        }
        if (
            in_array('sendgrid/sendgrid', $packages, true)
            || $hasKeyPrefix('SENDGRID_')
        ) {
            $integrations[] = 'SendGrid';
            $this->addEntry($entries, 'SENDGRID_API_KEY', 'Mail', '', required: true, optionalCommented: false, source: 'integration:sendgrid');
            $this->addEntry($entries, 'MAIL_FROM', 'Mail', 'noreply@example.com', required: true, optionalCommented: false, source: 'integration:sendgrid');
        }
        if (
            str_contains($allSignals, 'smtptransport')
            || $hasKeyPrefix('SMTP_')
        ) {
            $integrations[] = 'SMTP Mail';
            $this->addEntry($entries, 'SMTP_HOST', 'Mail', '127.0.0.1', required: true, optionalCommented: false, source: 'integration:smtp');
            $this->addEntry($entries, 'SMTP_PORT', 'Mail', '587', required: true, optionalCommented: false, source: 'integration:smtp');
            $this->addEntry($entries, 'SMTP_USER', 'Mail', '', required: true, optionalCommented: false, source: 'integration:smtp');
            $this->addEntry($entries, 'SMTP_PASS', 'Mail', '', required: true, optionalCommented: false, source: 'integration:smtp');
            $this->addEntry($entries, 'MAIL_FROM', 'Mail', 'noreply@example.com', required: true, optionalCommented: false, source: 'integration:smtp');
        }

        // Auth / Identity: Clerk & Auth0
        if (
            $this->hasPackageMatching($packages, 'clerk')
            || $hasKeyPrefix('CLERK_')
        ) {
            $integrations[] = 'Clerk';
            $this->addEntry($entries, 'CLERK_PUBLISHABLE_KEY', 'Auth & Identity', '', required: true, optionalCommented: false, source: 'integration:clerk');
            $this->addEntry($entries, 'CLERK_SECRET_KEY', 'Auth & Identity', '', required: true, optionalCommented: false, source: 'integration:clerk');
        }
        if (
            in_array('auth0/auth0-php', $packages, true)
            || $hasKeyPrefix('AUTH0_')
        ) {
            $integrations[] = 'Auth0';
            $this->addEntry($entries, 'AUTH0_DOMAIN', 'Auth & Identity', '', required: true, optionalCommented: false, source: 'integration:auth0');
            $this->addEntry($entries, 'AUTH0_CLIENT_ID', 'Auth & Identity', '', required: true, optionalCommented: false, source: 'integration:auth0');
            $this->addEntry($entries, 'AUTH0_CLIENT_SECRET', 'Auth & Identity', '', required: true, optionalCommented: false, source: 'integration:auth0');
        }

        // Messaging: Twilio & Slack
        if (
            in_array('twilio/sdk', $packages, true)
            || $hasKeyPrefix('TWILIO_')
        ) {
            $integrations[] = 'Twilio';
            $this->addEntry($entries, 'TWILIO_ACCOUNT_SID', 'Messaging', '', required: true, optionalCommented: false, source: 'integration:twilio');
            $this->addEntry($entries, 'TWILIO_AUTH_TOKEN', 'Messaging', '', required: true, optionalCommented: false, source: 'integration:twilio');
            $this->addEntry($entries, 'TWILIO_FROM', 'Messaging', '', required: true, optionalCommented: false, source: 'integration:twilio');
        }
        if ($hasKeyPrefix('SLACK_')) {
            $integrations[] = 'Slack';
            if (!isset($scan['keys']['SLACK_BOT_TOKEN'])) {
                $this->addEntry($entries, 'SLACK_WEBHOOK_URL', 'Messaging', '', required: true, optionalCommented: false, source: 'integration:slack');
            }
        }

        // Observability: Sentry & OpenTelemetry
        if (
            in_array('sentry/sentry', $packages, true)
            || str_contains($allSignals, 'sentry\\')
            || $hasKeyPrefix('SENTRY_')
        ) {
            $integrations[] = 'Sentry';
            $this->addEntry($entries, 'SENTRY_DSN', 'Observability', '', required: true, optionalCommented: false, source: 'integration:sentry');
        }
        if (
            $this->hasPackageMatching($packages, 'open-telemetry/')
            || $hasKeyPrefix('OTEL_')
        ) {
            $integrations[] = 'OpenTelemetry';
            $this->addEntry($entries, 'OTEL_EXPORTER_OTLP_ENDPOINT', 'Observability', 'http://127.0.0.1:4318', required: true, optionalCommented: false, source: 'integration:otel');
        }

        // AI Companions & Providers (optional commented unless explicitly read in app code)
        $usesAi = in_array('kongono/framework', $packages, true)
            || str_contains($allSignals, 'aiclient')
            || str_contains($allSignals, 'devstudiocompanions')
            || str_contains($allSignals, 'oshietutor')
            || str_contains($allSignals, 'chiebuilder')
            || str_contains($allSignals, 'hanteidebugger')
            || $hasKeyPrefix('OPENAI_')
            || $hasKeyPrefix('ANTHROPIC_')
            || $hasKeyPrefix('GEMINI_')
            || $hasKeyPrefix('GROQ_')
            || $hasKeyPrefix('OLLAMA_');
        if ($usesAi) {
            $integrations[] = 'AI Companions';
            $aiProviders = [
                ['ANTHROPIC_API_KEY', ''],
                ['GEMINI_API_KEY', ''],
                ['GROQ_API_KEY', ''],
                ['OLLAMA_HOST', 'http://127.0.0.1:11434'],
                ['OPENAI_API_KEY', ''],
            ];
            foreach ($aiProviders as $idx => [$aiKey, $aiPlaceholder]) {
                $explicitlyUsed = isset($scan['keys'][$aiKey]);
                $this->addEntry(
                    $entries,
                    $aiKey,
                    'AI Companions',
                    $aiPlaceholder,
                    required: $explicitlyUsed,
                    optionalCommented: !$explicitlyUsed,
                    source: 'integration:ai',
                    comment: 0 === $idx ? 'Set any one AI provider for Oshie, Chie & Hantei:' : null,
                );
            }
        }

        $integrations = array_values(array_unique($integrations));
        $orderedEntries = $this->orderEntries($entries);
        $detectedByKey = [];
        foreach ($orderedEntries as $entry) {
            $detectedByKey[$entry['key']] = $entry;
        }

        $parsedExisting = $this->parseExistingEnvExample($existingContent);
        $existingActive = $parsedExisting['active'];
        $existingAll = $parsedExisting['all'];

        /** @var list<string> $missingKeys */
        $missingKeys = [];
        /** @var list<array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>}> $entriesToAdd */
        $entriesToAdd = [];
        foreach ($orderedEntries as $entry) {
            $key = $entry['key'];
            if ($entry['required']) {
                if (!isset($existingActive[$key])) {
                    $missingKeys[] = $key;
                    if (!$exists || !isset($existingAll[$key])) {
                        $entriesToAdd[] = $entry;
                    } else {
                        // Key existed only as a comment in `.env.example`, now actively required by code/packages
                        $entriesToAdd[] = $entry;
                    }
                }
            } elseif (!isset($existingAll[$key])) {
                $entriesToAdd[] = $entry;
            }
        }

        /** @var list<string> $staleKeys */
        $staleKeys = [];
        foreach (array_keys($existingActive) as $existingKey) {
            if (!isset($detectedByKey[$existingKey]) && !in_array($existingKey, self::BASELINE_KEYS, true)) {
                $staleKeys[] = $existingKey;
            }
        }

        /** @var list<string> $addedKeys */
        $addedKeys = array_map(static fn(array $e): string => $e['key'], $entriesToAdd);
        /** @var list<string> $prunedKeys */
        $prunedKeys = [];

        if (!$exists) {
            $targetContent = $this->renderFresh($orderedEntries);
        } else {
            [$targetContent, $prunedKeys] = $this->mergeIntoExisting(
                $existingContent,
                $entriesToAdd,
                $prune ? $staleKeys : [],
            );
        }

        $changed = !$exists || $targetContent !== $existingContent;
        $wrote = false;
        if ($write && $changed && is_dir($root)) {
            $wrote = false !== file_put_contents($examplePath, $targetContent, LOCK_EX);
        }

        $diffLines = [];
        foreach ($entriesToAdd as $entry) {
            $diffLines[] = '+ ' . $this->formatLine($entry);
        }
        foreach ($prunedKeys as $prunedKey) {
            $diffLines[] = '- ' . $prunedKey;
        }

        return [
            'exists' => $exists || $wrote,
            'in_sync' => ($exists || $wrote) && ([] === $missingKeys || $wrote),
            'changed' => $changed,
            'wrote' => $wrote,
            'path' => str_replace('\\', '/', $examplePath),
            'detected_integrations' => $integrations,
            'detected_keys' => $orderedEntries,
            'missing_keys' => $wrote ? [] : $missingKeys,
            'stale_keys' => $wrote && $prune ? [] : $staleKeys,
            'added_keys' => $addedKeys,
            'pruned_keys' => $prunedKeys,
            'content' => $targetContent,
            'diff_preview' => implode("\n", $diffLines),
        ];
    }

    /**
     * Determine whether an env key name represents sensitive material that must never carry a real value.
     */
    public static function isSensitiveKey(string $key): bool
    {
        if (SecretScrubber::isSensitiveKey($key)) {
            return true;
        }
        $upper = strtoupper(trim($key));
        if (in_array($upper, ['APP_KEY', 'DATABASE_URL', 'REDIS_URL', 'SENTRY_DSN'], true)) {
            return true;
        }
        foreach (self::EXTRA_SENSITIVE_SUFFIXES as $suffix) {
            if (str_ends_with($upper, $suffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Produce a strictly non-sensitive placeholder value for `.env.example`.
     */
    public static function sanitizePlaceholder(string $key, ?string $rawDefault = null): string
    {
        $upper = strtoupper(trim($key));

        if ('DATABASE_URL' === $upper) {
            $candidate = null !== $rawDefault ? trim($rawDefault) : '';
            if (
                str_starts_with($candidate, 'pgsql://postgres:CHANGE_ME@')
                || str_starts_with($candidate, 'mysql://root:CHANGE_ME@')
                || str_starts_with($candidate, 'sqlite://')
            ) {
                return $candidate;
            }

            return 'sqlite://var/app.sqlite';
        }

        $fixed = match ($upper) {
            'APP_KEY' => 'REPLACE_WITH_kongo_key_generate',
            'APP_DEBUG' => 'false',
            'APP_ENV' => 'local',
            'SESSION_SECURE' => 'false',
            'REDIS_URL' => 'redis://127.0.0.1:6379/0',
            'OLLAMA_HOST' => 'http://127.0.0.1:11434',
            'SUPABASE_URL' => 'https://your-project.supabase.co',
            'OTEL_EXPORTER_OTLP_ENDPOINT' => 'http://127.0.0.1:4318',
            'MAIL_FROM' => 'noreply@example.com',
            'S3_REGION' => 'us-east-1',
            default => null,
        };
        if (null !== $fixed) {
            return $fixed;
        }

        if (self::isSensitiveKey($upper)) {
            return '';
        }

        if (null === $rawDefault) {
            return '';
        }

        $trimmed = trim($rawDefault);
        if ('' === $trimmed || strlen($trimmed) > 120 || 1 === preg_match('/[\r\n\0]/', $trimmed)) {
            return '';
        }

        // Second defense layer: if SecretScrubber mutates the literal default, treat it as secret and blank it out
        if (SecretScrubber::scrub($trimmed) !== $trimmed) {
            return '';
        }

        if (1 === preg_match('/[\s#"\']/', $trimmed)) {
            return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $trimmed) . '"';
        }

        return $trimmed;
    }

    /**
     * @param array<string, array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>}> $entries
     */
    private function addEntry(
        array &$entries,
        string $key,
        string $section,
        string $placeholder,
        bool $required,
        bool $optionalCommented,
        string $source,
        ?string $comment = null,
        bool $preferExplicit = false,
    ): void {
        $upper = strtoupper(trim($key));
        if ('' === $upper || 1 !== preg_match('/\A[A-Z][A-Z0-9_]{1,63}\z/', $upper)) {
            return;
        }
        $safePlaceholder = self::sanitizePlaceholder($upper, '' !== $placeholder ? $placeholder : null);
        if ('' !== $placeholder && '' === $safePlaceholder && in_array($upper, ['APP_KEY', 'DATABASE_URL', 'REDIS_URL'], true)) {
            $safePlaceholder = $placeholder;
        }

        if (isset($entries[$upper])) {
            $existing = $entries[$upper];
            if (!in_array($source, $existing['sources'], true)) {
                $existing['sources'][] = $source;
            }
            if ($required) {
                $existing['required'] = true;
                $existing['optional_commented'] = false;
            }
            if ('Custom Application' === $existing['section'] && 'Custom Application' !== $section) {
                $existing['section'] = $section;
            }
            if ('' === $existing['placeholder'] && '' !== $safePlaceholder) {
                $existing['placeholder'] = $safePlaceholder;
            } elseif ($preferExplicit && '' !== $safePlaceholder && 'Application' !== $existing['section']) {
                $existing['placeholder'] = $safePlaceholder;
            }
            if (null === $existing['comment'] && null !== $comment) {
                $existing['comment'] = $comment;
            }
            $entries[$upper] = $existing;

            return;
        }

        $entries[$upper] = [
            'key' => $upper,
            'section' => $section,
            'placeholder' => $safePlaceholder,
            'required' => $required,
            'optional_commented' => $optionalCommented,
            'sensitive' => self::isSensitiveKey($upper),
            'comment' => $comment,
            'sources' => [$source],
        ];
    }

    /**
     * @return list<string>
     */
    private function readComposerPackages(string $root): array
    {
        $composerPath = $root . DIRECTORY_SEPARATOR . 'composer.json';
        if (!is_file($composerPath) || is_link($composerPath)) {
            return [];
        }
        $raw = file_get_contents($composerPath);
        if (false === $raw) {
            return [];
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded) || !is_array($decoded['require'] ?? null)) {
            return [];
        }

        $pkgs = [];
        foreach (array_keys($decoded['require']) as $name) {
            if (is_string($name) && '' !== $name) {
                $pkgs[] = strtolower($name);
            }
        }

        return $pkgs;
    }

    /**
     * @param list<string> $packages
     */
    private function hasPackageMatching(array $packages, string $needle): bool
    {
        foreach ($packages as $pkg) {
            if (str_contains($pkg, $needle)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private function collectGraphSignals(?ApplicationGraph $graph): array
    {
        if (null === $graph) {
            return [];
        }

        $signals = $graph->middleware;
        foreach ($graph->services as $svc) {
            $signals[] = $svc->id;
        }

        return $signals;
    }

    /**
     * @return array{
     *     keys: array<string, array{default: ?string, sources: list<string>}>,
     *     signals: list<string>
     * }
     */
    private function scanProjectSources(string $root): array
    {
        /** @var array<string, array{default: ?string, sources: list<string>}> $keys */
        $keys = [];
        /** @var list<string> $signals */
        $signals = [];
        $rootPrefix = $root . DIRECTORY_SEPARATOR;

        foreach (self::SCAN_DIRS as $dirName) {
            $dirPath = $root . DIRECTORY_SEPARATOR . $dirName;
            if (!is_dir($dirPath) || is_link($dirPath)) {
                continue;
            }
            $dirIt = new RecursiveDirectoryIterator($dirPath, FilesystemIterator::SKIP_DOTS);
            $filter = new RecursiveCallbackFilterIterator(
                $dirIt,
                static function (SplFileInfo $cur): bool {
                    if ($cur->isLink()) {
                        return false;
                    }
                    if ($cur->isDir()) {
                        return !in_array($cur->getFilename(), self::IGNORED_DIRS, true);
                    }

                    return true;
                },
            );
            $it = new RecursiveIteratorIterator($filter);
            foreach ($it as $file) {
                if (!$file instanceof SplFileInfo || !$file->isFile() || $file->isLink()) {
                    continue;
                }
                if (!str_ends_with(strtolower($file->getFilename()), '.php')) {
                    continue;
                }
                if ($file->getSize() > self::MAX_SCAN_FILE_BYTES) {
                    continue;
                }
                $realFile = realpath($file->getPathname());
                if (false === $realFile || !str_starts_with($realFile, $rootPrefix)) {
                    continue;
                }
                $raw = file_get_contents($realFile);
                if (false === $raw) {
                    continue;
                }
                $rel = str_replace('\\', '/', substr($realFile, strlen($rootPrefix)));
                $this->scanPhpSource($raw, $rel, $keys, $signals);
            }
        }

        return [
            'keys' => $keys,
            'signals' => array_values(array_unique($signals)),
        ];
    }

    /**
     * @param array<string, array{default: ?string, sources: list<string>}> $keys
     * @param list<string>                                                  $signals
     */
    private function scanPhpSource(string $source, string $relPath, array &$keys, array &$signals): void
    {
        // Fast signal extraction for imports / class names / integration markers
        $signalChecks = [
            'Stripe\\' => 'stripe\\',
            'Supabase' => 'supabase',
            'supabase.co' => 'supabase',
            'PdoConnection' => 'pdoconnection',
            'ConnectionInterface' => 'connectioninterface',
            'pgsql:' => 'pgsql',
            'pgsql://' => 'pgsql',
            'postgres' => 'postgres',
            'RedisCache' => 'rediscache',
            'RedisClient' => 'redisclient',
            'RedisQueueDriver' => 'redisqueuedriver',
            'S3Storage' => 's3storage',
            'ResendTransport' => 'resendtransport',
            'PostmarkTransport' => 'postmarktransport',
            'SmtpTransport' => 'smtptransport',
            'SessionMiddleware' => 'sessionmiddleware',
            'Sentry\\' => 'sentry\\',
            'AiClient' => 'aiclient',
            'DevStudioCompanions' => 'devstudiocompanions',
            'OshieTutor' => 'oshietutor',
            'ChieBuilder' => 'chiebuilder',
            'HanteiDebugger' => 'hanteidebugger',
        ];
        foreach ($signalChecks as $needle => $tag) {
            if (false !== stripos($source, $needle)) {
                $signals[] = $tag;
            }
        }

        $tokens = PhpToken::tokenize($source);
        $sig = [];
        foreach ($tokens as $tok) {
            if (in_array($tok->id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            $sig[] = $tok;
        }

        $count = count($sig);
        for ($i = 0; $i < $count; ++$i) {
            $tok = $sig[$i];

            // Pattern 1: Config::env('KEY'[, 'default']) [?? 'default']
            if (
                T_STRING === $tok->id
                && 'Config' === $tok->text
                && $i + 3 < $count
                && T_DOUBLE_COLON === $sig[$i + 1]->id
                && T_STRING === $sig[$i + 2]->id
                && 'env' === strtolower($sig[$i + 2]->text)
                && '(' === $sig[$i + 3]->text
            ) {
                [$key, $default, $closeIdx] = $this->parseEnvCallArgs($sig, $i + 3);
                if (null !== $key) {
                    if (null === $default && null !== $closeIdx) {
                        $default = $this->extractCoalesceDefault($sig, $closeIdx + 1);
                    }
                    $this->recordDiscoveredKey($keys, $key, $default, $relPath . ':' . $tok->line);
                }
                continue;
            }

            // Pattern 2: getenv('KEY') [?: 'default']
            if (
                T_STRING === $tok->id
                && 'getenv' === strtolower($tok->text)
                && $i + 1 < $count
                && '(' === $sig[$i + 1]->text
                && (0 === $i || !in_array($sig[$i - 1]->id, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true))
            ) {
                [$key, $default, $closeIdx] = $this->parseEnvCallArgs($sig, $i + 1);
                if (null !== $key) {
                    if (null === $default && null !== $closeIdx) {
                        $default = $this->extractCoalesceDefault($sig, $closeIdx + 1);
                    }
                    $this->recordDiscoveredKey($keys, $key, $default, $relPath . ':' . $tok->line);
                }
                continue;
            }

            // Pattern 3: $_ENV['KEY'] or $_SERVER['KEY']
            if (
                T_VARIABLE === $tok->id
                && ('$_ENV' === $tok->text || '$_SERVER' === $tok->text)
                && $i + 3 < $count
                && '[' === $sig[$i + 1]->text
                && T_CONSTANT_ENCAPSED_STRING === $sig[$i + 2]->id
                && ']' === $sig[$i + 3]->text
            ) {
                $key = $this->unquoteString($sig[$i + 2]->text);
                if (null === $key) {
                    continue;
                }
                if ('$_SERVER' === $tok->text && $this->isIgnoredServerKey($key)) {
                    continue;
                }
                $default = $this->extractCoalesceDefault($sig, $i + 4);
                $this->recordDiscoveredKey($keys, $key, $default, $relPath . ':' . $tok->line);
            }
        }
    }

    /**
     * @param list<PhpToken> $sig
     * @return array{0: ?string, 1: ?string, 2: ?int}
     */
    private function parseEnvCallArgs(array $sig, int $openParenIdx): array
    {
        $count = count($sig);
        $depth = 0;
        $argIndex = 0;
        $argTokens = [];
        $current = [];
        $closeIdx = null;

        for ($j = $openParenIdx; $j < $count; ++$j) {
            $t = $sig[$j];
            if ('(' === $t->text) {
                ++$depth;
                if (1 === $depth) {
                    continue;
                }
            } elseif (')' === $t->text) {
                --$depth;
                if (0 === $depth) {
                    if ([] !== $current) {
                        $argTokens[$argIndex] = $current;
                    }
                    $closeIdx = $j;
                    break;
                }
            } elseif (',' === $t->text && 1 === $depth) {
                $argTokens[$argIndex] = $current;
                ++$argIndex;
                $current = [];
                continue;
            }
            $current[] = $t;
        }

        $key = null;
        $default = null;
        foreach ($argTokens as $idx => $tokens) {
            // Support PHP 8 named arguments (`name: 'FOO'`, `default: 'bar'`)
            $argName = null;
            if (count($tokens) >= 2 && T_STRING === $tokens[0]->id && ':' === $tokens[1]->text) {
                $argName = strtolower($tokens[0]->text);
                $tokens = array_slice($tokens, 2);
            }
            if (1 !== count($tokens) || T_CONSTANT_ENCAPSED_STRING !== $tokens[0]->id) {
                continue;
            }
            $val = $this->unquoteString($tokens[0]->text);
            if ('name' === $argName || (null === $argName && 0 === $idx)) {
                $key = $val;
            } elseif ('default' === $argName || (null === $argName && 1 === $idx)) {
                $default = $val;
            }
        }

        return [$key, $default, $closeIdx];
    }

    /**
     * @param list<PhpToken> $sig
     */
    private function extractCoalesceDefault(array $sig, int $idx): ?string
    {
        $count = count($sig);
        if ($idx + 1 >= $count) {
            return null;
        }
        if (T_COALESCE === $sig[$idx]->id && T_CONSTANT_ENCAPSED_STRING === $sig[$idx + 1]->id) {
            return $this->unquoteString($sig[$idx + 1]->text);
        }

        return null;
    }

    private function unquoteString(string $literal): ?string
    {
        if (strlen($literal) < 2) {
            return null;
        }
        $quote = $literal[0];
        if ("'" !== $quote && '"' !== $quote) {
            return null;
        }
        $inner = substr($literal, 1, -1);
        if ('"' === $quote && str_contains($inner, '$')) {
            return null;
        }

        return stripcslashes($inner);
    }

    private function isIgnoredServerKey(string $key): bool
    {
        $upper = strtoupper(trim($key));
        if (in_array($upper, self::IGNORED_SERVER_KEYS, true)) {
            return true;
        }

        return str_starts_with($upper, 'HTTP_')
            || str_starts_with($upper, 'LD_')
            || str_starts_with($upper, 'DYLD_')
            || str_starts_with($upper, 'PHP_INI_')
            || str_starts_with($upper, 'ZEND_')
            || str_starts_with($upper, 'BASH_')
            || str_starts_with($upper, 'XDEBUG_');
    }

    /**
     * @param array<string, array{default: ?string, sources: list<string>}> $keys
     */
    private function recordDiscoveredKey(array &$keys, string $key, ?string $default, string $source): void
    {
        $upper = strtoupper(trim($key));
        if (1 !== preg_match('/\A[A-Z][A-Z0-9_]{1,63}\z/', $upper) || $this->isIgnoredServerKey($upper)) {
            return;
        }

        if (!isset($keys[$upper])) {
            $keys[$upper] = ['default' => $default, 'sources' => [$source]];

            return;
        }

        if (null === $keys[$upper]['default'] && null !== $default) {
            $keys[$upper]['default'] = $default;
        }
        if (!in_array($source, $keys[$upper]['sources'], true)) {
            $keys[$upper]['sources'][] = $source;
        }
    }

    private function inferSectionForKey(string $key): string
    {
        return match (true) {
            str_starts_with($key, 'APP_'),
            str_starts_with($key, 'SESSION_'),
            str_starts_with($key, 'LOG_'),
            'TRUSTED_PROXIES' === $key => 'Application',
            str_starts_with($key, 'DATABASE_'),
            str_starts_with($key, 'DB_'),
            str_starts_with($key, 'POSTGRES_'),
            str_starts_with($key, 'MYSQL_') => 'Database',
            str_starts_with($key, 'REDIS_'),
            str_starts_with($key, 'CACHE_'),
            str_starts_with($key, 'QUEUE_') => 'Cache & Queue',
            str_starts_with($key, 'S3_'),
            str_starts_with($key, 'R2_'),
            str_starts_with($key, 'STORAGE_') => 'Storage',
            str_starts_with($key, 'MAIL_'),
            str_starts_with($key, 'SMTP_'),
            str_starts_with($key, 'RESEND_'),
            str_starts_with($key, 'POSTMARK_'),
            str_starts_with($key, 'SENDGRID_') => 'Mail',
            str_starts_with($key, 'STRIPE_') => 'Stripe',
            str_starts_with($key, 'SUPABASE_') => 'Supabase',
            str_starts_with($key, 'CLERK_'),
            str_starts_with($key, 'AUTH0_'),
            str_starts_with($key, 'OAUTH_') => 'Auth & Identity',
            str_starts_with($key, 'TWILIO_'),
            str_starts_with($key, 'SLACK_') => 'Messaging',
            str_starts_with($key, 'SENTRY_'),
            str_starts_with($key, 'OTEL_') => 'Observability',
            str_starts_with($key, 'OPENAI_'),
            str_starts_with($key, 'ANTHROPIC_'),
            str_starts_with($key, 'GEMINI_'),
            str_starts_with($key, 'GROQ_'),
            str_starts_with($key, 'OLLAMA_') => 'AI Companions',
            default => 'Custom Application',
        };
    }

    /**
     * @param array<string, array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>}> $entries
     * @return list<array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>}>
     */
    private function orderEntries(array $entries): array
    {
        $rank = array_flip(self::SECTION_ORDER);
        $list = array_values($entries);
        usort($list, static function (array $a, array $b) use ($rank): int {
            $ra = $rank[$a['section']] ?? 999;
            $rb = $rank[$b['section']] ?? 999;
            if ($ra !== $rb) {
                return $ra <=> $rb;
            }
            $ba = array_search($a['key'], self::BASELINE_KEYS, true);
            $bb = array_search($b['key'], self::BASELINE_KEYS, true);
            if (false !== $ba || false !== $bb) {
                return (false !== $ba ? $ba : 99) <=> (false !== $bb ? $bb : 99);
            }

            return strcmp($a['key'], $b['key']);
        });

        return $list;
    }

    /**
     * @return array{active: array<string, true>, all: array<string, true>}
     */
    private function parseExistingEnvExample(string $content): array
    {
        $active = [];
        $all = [];
        if ('' === $content) {
            return ['active' => $active, 'all' => $all];
        }

        $split = preg_split('/\r\n|\r|\n/', $content);
        foreach (false !== $split ? $split : [] as $line) {
            $trimmed = trim($line);
            if ('' === $trimmed) {
                continue;
            }
            if (str_starts_with($trimmed, '#')) {
                $uncommented = ltrim(substr($trimmed, 1));
                if (1 === preg_match('/\A(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=/', $uncommented, $m)) {
                    $all[$m[1]] = true;
                }
                continue;
            }
            if (1 === preg_match('/\A(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=/', $trimmed, $m)) {
                $active[$m[1]] = true;
                $all[$m[1]] = true;
            }
        }

        return ['active' => $active, 'all' => $all];
    }

    /**
     * @param list<array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>}> $entries
     */
    private function renderFresh(array $entries): string
    {
        $lines = [];
        $currentSection = null;
        foreach ($entries as $entry) {
            if ($entry['section'] !== $currentSection) {
                if (null !== $currentSection) {
                    $lines[] = '';
                    $lines[] = '# ' . $entry['section'];
                }
                $currentSection = $entry['section'];
            }
            if (null !== $entry['comment']) {
                $lines[] = '# ' . $entry['comment'];
            }
            $lines[] = $this->formatLine($entry);
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * @param list<array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>}> $entriesToAdd
     * @param list<string>                                                                                                                                                       $keysToPrune
     * @return array{0: string, 1: list<string>}
     */
    private function mergeIntoExisting(string $existingContent, array $entriesToAdd, array $keysToPrune): array
    {
        $lineEnding = str_contains($existingContent, "\r\n") ? "\r\n" : "\n";
        $normalized = str_replace("\r\n", "\n", $existingContent);
        $rawLines = explode("\n", rtrim($normalized, "\n"));

        /** @var array<string, array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>}> $promoteCommented */
        $promoteCommented = [];
        foreach ($entriesToAdd as $entry) {
            if ($entry['required']) {
                $promoteCommented[$entry['key']] = $entry;
            }
        }

        $pruneLookup = array_fill_keys($keysToPrune, true);
        /** @var list<string> $pruned */
        $pruned = [];
        /** @var array<string, true> $promoted */
        $promoted = [];
        $keptLines = [];

        foreach ($rawLines as $line) {
            $trimmed = trim($line);
            if ('' !== $trimmed && !str_starts_with($trimmed, '#') && 1 === preg_match('/\A(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=/', $trimmed, $m)) {
                if (isset($pruneLookup[$m[1]])) {
                    $pruned[] = $m[1];
                    continue;
                }
            }
            if (str_starts_with($trimmed, '#')) {
                $uncommented = ltrim(substr($trimmed, 1));
                if (1 === preg_match('/\A(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=/', $uncommented, $m) && isset($promoteCommented[$m[1]])) {
                    $keptLines[] = $this->formatLine($promoteCommented[$m[1]]);
                    $promoted[$m[1]] = true;
                    continue;
                }
            }
            $keptLines[] = $line;
        }

        $remainingAdditions = array_values(array_filter(
            $entriesToAdd,
            static fn(array $e): bool => !isset($promoted[$e['key']]),
        ));

        if ([] !== $remainingAdditions) {
            $currentSection = null;
            foreach ($remainingAdditions as $entry) {
                if ($entry['section'] !== $currentSection) {
                    if ([] !== $keptLines && '' !== end($keptLines)) {
                        $keptLines[] = '';
                    }
                    $keptLines[] = '# ' . $entry['section'];
                    $currentSection = $entry['section'];
                }
                if (null !== $entry['comment']) {
                    $keptLines[] = '# ' . $entry['comment'];
                }
                $keptLines[] = $this->formatLine($entry);
            }
        }

        $merged = implode("\n", $keptLines) . "\n";
        if ("\r\n" === $lineEnding) {
            $merged = str_replace("\n", "\r\n", $merged);
        }

        return [$merged, $pruned];
    }

    /**
     * @param array{key: string, section: string, placeholder: string, required: bool, optional_commented: bool, sensitive: bool, comment: ?string, sources: list<string>} $entry
     */
    private function formatLine(array $entry): string
    {
        $prefix = $entry['optional_commented'] ? '# ' : '';

        return $prefix . $entry['key'] . '=' . $entry['placeholder'];
    }
}
