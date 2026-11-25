<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

use ArgumentCountError;
use Error;
use Kongono\Core\CoreException;
use ParseError;
use PDOException;
use ReflectionClass;
use ReflectionMethod;
use Throwable;
use TypeError;

/**
 * IDE-grade, offline, deterministic 5W1H error explainer for Kongono & PHP 8.5.
 *
 * Translates raw exceptions, HTTP 4xx errors, compiled view cache hashes, reflection typos,
 * SQL/PDO failures, CSRF rejections, DI mismatches, and Zokeibi component errors into clear
 * everyday language ("Who, What, Why, Where, When, How to fix") for both humans and AI agents.
 */
final readonly class ErrorExplainer
{
    /**
     * Explain any PHP/Kongono Throwable with full 5W1H context.
     *
     * @param list<string> $availableRoutes Optional registered route signatures (`METHOD /path`) for 404/405 hints
     */
    public function explainThrowable(
        Throwable $exception,
        ?string $method = null,
        ?string $path = null,
        ?string $basePath = null,
        string $kongoBin = 'php vendor/bin/kongo',
        array $availableRoutes = [],
        ?string $timestampUtc = null,
    ): ErrorExplanation {
        $when = $this->formatWhen($method, $path, $timestampUtc);
        $rawFile = $exception->getFile();
        $rawLine = $exception->getLine();

        // Automatically resolve compiled `.kgn.html` view cache files back to the real template path!
        $sourceMap = $this->resolveCompiledViewSource($rawFile);
        $resolvedFile = null !== $sourceMap ? $sourceMap['template_path'] : $this->relativePath($rawFile, $basePath);
        $resolvedLine = $rawLine;
        $where = null !== $sourceMap
            ? sprintf('%s (compiled cache line %d)%s', $sourceMap['template_path'], $rawLine, $this->routeSuffix($method, $path))
            : sprintf('%s:%d%s', $resolvedFile, $rawLine, $this->routeSuffix($method, $path));

        $safeMessage = SecretScrubber::scrub($exception->getMessage());
        $lower = strtolower($safeMessage);
        $who = $this->inferWho($exception, $resolvedFile, null !== $sourceMap);

        // 1. Explicit Kongono CoreException carrying a structured Diagnostic
        if ($exception instanceof CoreException && null !== $exception->diagnostic) {
            $safe = $exception->diagnostic->toSafeArray();
            $cmd = $this->extractCommand($safe['remediation']);
            $steps = '' !== trim($safe['remediation'])
                ? [$safe['remediation']]
                : ['Inspect the Safe Diagnostic fields and the highlighted source frame below.'];

            return new ErrorExplanation(
                code: $safe['id'],
                who: $who,
                what: $safe['title'],
                why: '' !== $safeMessage ? $safeMessage : $safe['title'],
                where: $where,
                when: $when,
                howToFix: $steps,
                command: $cmd,
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 2. Compiled `.kgn.html` View Syntax / Parse Error
        if ($exception instanceof ParseError && null !== $sourceMap) {
            return new ErrorExplanation(
                code: 'KGN-ERR-VIEW-SYNTAX',
                who: 'Kongono ViewEngine (Template Compiler)',
                what: sprintf('Syntax error while compiling template "%s".', $sourceMap['template_name']),
                why: sprintf('The `.kgn.html` template compiled into invalid PHP (%s). Common causes: placing multiple `@if (...)` directives on the same line, putting parentheses `()` inside a single-line `@section(\'title\', \'...\')` string, or an unclosed `@if`/`@foreach`/`@php` block.', $safeMessage),
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Open `%s` and check for unclosed directives or inline `@if (...)` / `@section(..., ...)` containing parentheses.', $sourceMap['template_path']),
                    'Put each `@if (...)` on its own line, or use ternary `{{ $cond ? \'a\' : \'b\' }}` inside HTML attributes.',
                    'Clear compiled view cache and reload.',
                ],
                codeFix: "// Avoid two @if directives on one line or ')' inside inline @section:\n@section('title')\n  My Page (Beta)\n@endsection",
                command: $kongoBin . ' cache:clear',
                sourceFile: $sourceMap['template_path'],
                sourceLine: null,
            );
        }

        // 3. Missing Zokeibi `<x-ui.*>` Component Template
        if (1 === preg_match('#components/ui/([a-z0-9_-]+)#i', $safeMessage, $km) && (str_contains($lower, 'not found') || str_contains($lower, 'does not exist'))) {
            $compId = strtolower($km[1]);

            return new ErrorExplanation(
                code: 'KGN-ERR-ZOKEIBI-COMPONENT-MISSING',
                who: 'Zokeibi UI / Kongono ViewEngine',
                what: sprintf('Zokeibi component `<x-ui.%s>` is not installed in your app views yet.', $compId),
                why: sprintf('Your template rendered `<x-ui.%s>`, which looks for `views/components/ui/%s.kgn.html`, but that file does not exist yet.', $compId, $compId),
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Install the `<x-ui.%s>` component directly into your app\'s `views/components/ui/` folder.', $compId),
                    'Rebuild your tree-shaken Zokeibi CSS bundle so the component\'s styles are included.',
                    'Check for typos with `php vendor/bin/zokeibi list`.',
                ],
                command: sprintf('php vendor/bin/zokeibi add %s && php vendor/bin/zokeibi build', $compId),
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 4. View Template Not Found (with Levenshtein "Did you mean?" across views/)
        if ((str_contains($lower, 'template') || str_contains($lower, 'view')) && (str_contains($lower, 'not found') || str_contains($lower, 'does not exist'))) {
            $missingView = $this->extractQuoted($safeMessage);
            $suggestions = null !== $missingView && null !== $basePath
                ? $this->suggestSimilarViews($missingView, $basePath)
                : [];

            return new ErrorExplanation(
                code: 'KGN-ERR-VIEW-NOT-FOUND',
                who: 'Kongono ViewEngine (Template Lookup)',
                what: null !== $missingView
                    ? sprintf('Could not find view template "%s".', $missingView)
                    : 'Could not find the requested `.kgn.html` view template.',
                why: 'Kongono looks for templates relative to your `views/` folder with the `.kgn.html` extension (for example, `pages/home` maps to `views/pages/home.kgn.html`).',
                where: $where,
                when: $when,
                howToFix: [
                    null !== $missingView
                        ? sprintf('Verify that `views/%s.kgn.html` exists and the casing matches exactly (Linux servers are case-sensitive).', ltrim($missingView, '/'))
                        : 'Verify the `.kgn.html` file exists under `views/` with matching spelling and case.',
                    [] !== $suggestions
                        ? sprintf('Did you mean `%s`? Update the name passed to `$views->render(...)`.', $suggestions[0])
                        : 'Create the template file or update the name passed to `$views->render(...)`.',
                ],
                command: $kongoBin . ' cache:clear',
                didYouMean: $suggestions,
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 5. Call to Undefined Method — Live PHP Reflection + Levenshtein "Did you mean?"
        if (1 === preg_match('/Call to undefined method ([a-zA-Z0-9_\\\\]+)::([a-zA-Z0-9_]+)\(\)/', $safeMessage, $mm)) {
            $fqcn = $mm[1];
            $badMethod = $mm[2];
            $suggestions = $this->suggestSimilarMethods($fqcn, $badMethod);
            $shortClass = $this->shortClass($fqcn);

            return new ErrorExplanation(
                code: 'KGN-ERR-UNDEFINED-METHOD',
                who: sprintf('App Code calling `%s::%s()`', $shortClass, $badMethod),
                what: sprintf('Method `%s()` does not exist on `%s`.', $badMethod, $shortClass),
                why: [] !== $suggestions
                    ? sprintf('You called `->%s()`, which is not a public method on `%s`. The closest real method is `->%s()`.', $badMethod, $fqcn, $suggestions[0])
                    : sprintf('`%s` has no public method named `%s()`. Either the method name is misspelled, it is `private`/`protected`, or you expected a different object type.', $fqcn, $badMethod),
                where: $where,
                when: $when,
                howToFix: [
                    [] !== $suggestions
                        ? sprintf('Replace `->%s(...)` with `->%s(...)` at `%s:%d`.', $badMethod, $suggestions[0], $resolvedFile, $resolvedLine)
                        : sprintf('Open `%s:%d` and check the available methods on `%s`.', $resolvedFile, $resolvedLine, $shortClass),
                    'Run PHPStan Level 9 (`composer analyse`) to catch method typos before running requests.',
                ],
                codeFix: [] !== $suggestions
                    ? sprintf("// Replace:\n\$obj->%s(...);\n// With:\n\$obj->%s(...);", $badMethod, $suggestions[0])
                    : null,
                command: 'composer analyse',
                didYouMean: array_map(static fn(string $m): string => $shortClass . '::' . $m . '()', $suggestions),
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 6. Class or Interface Not Found
        if (1 === preg_match('/(?:Class|Interface|Trait)\s+"([^"]+)"\s+not found/i', $safeMessage, $cm)) {
            $missingClass = $cm[1];

            return new ErrorExplanation(
                code: 'KGN-ERR-CLASS-NOT-FOUND',
                who: 'PHP Autoloader (Composer PSR-4)',
                what: sprintf('PHP could not locate class `%s`.', $missingClass),
                why: 'Either a `use` import is missing at the top of the file, the namespace/filename casing does not match PSR-4 in `composer.json`, or Composer\'s autoload map is stale.',
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Check the `use %s;` import and namespace declaration for exact spelling and capitalization.', $missingClass),
                    'Verify the file\'s folder matches the `autoload.psr-4` mapping in `composer.json`.',
                    'Regenerate the autoloader with `composer dump-autoload`.',
                ],
                command: 'composer dump-autoload',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 7. Undefined Variable
        if (1 === preg_match('/Undefined variable \$([a-zA-Z0-9_]+)/', $safeMessage, $vm)) {
            $varName = $vm[1];
            $inView = null !== $sourceMap;

            return new ErrorExplanation(
                code: 'KGN-ERR-UNDEFINED-VARIABLE',
                who: $inView ? sprintf('View Template (%s)', $sourceMap['template_path']) : 'PHP Runtime (Local Scope)',
                what: sprintf('Variable `$%s` was used before it was defined.', $varName),
                why: $inView
                    ? sprintf('Your template `%s` reads `$%s`, but the controller did not pass `\'%s\' => ...` into `$views->render(...)`.', $sourceMap['template_path'], $varName, $varName)
                    : sprintf('`$%s` has not been assigned in this scope (often caused by a variable typo or an `if` branch that never assigned it).', $varName),
                where: $where,
                when: $when,
                howToFix: $inView
                    ? [
                        sprintf('Pass `\'%s\' => $value` in the data array when calling `$views->render(\'%s\', [...])`.', $varName, $sourceMap['template_name']),
                        sprintf('Or provide a fallback default inside the template: `{{ $%s ?? \'\' }}`.', $varName),
                    ]
                    : [
                        sprintf('Initialize `$%s` before reading it at `%s:%d`, or check for a spelling typo.', $varName, $resolvedFile, $resolvedLine),
                        sprintf('If the variable may be optional, guard with `$%s ?? null`.', $varName),
                    ],
                codeFix: $inView
                    ? sprintf("return Response::html(\$this->views->render('%s', [\n    '%s' => \$value,\n]));", $sourceMap['template_name'], $varName)
                    : sprintf("\$%s = \$%s ?? '';", $varName, $varName),
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 8. Undefined Array Key
        if (1 === preg_match('/Undefined array key "?([^"\n]+)"?/', $safeMessage, $akm)) {
            $key = $akm[1];

            return new ErrorExplanation(
                code: 'KGN-ERR-UNDEFINED-KEY',
                who: $who,
                what: sprintf('Tried to read array key `"%s"`, but that key does not exist in the array.', $key),
                why: 'PHP 8.5 treats missing array keys strictly. The input payload, query string, config array, or database row did not include this key.',
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Use the null-coalescing operator: `$array[\'%s\'] ?? null` (or a sensible default).', $key),
                    'If this comes from user input, validate it first with a typed Kongono DTO or `Validator`.',
                ],
                codeFix: sprintf("\$value = \$data['%s'] ?? '';", $key),
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 9. Calling Method or Reading Property on Null
        if (str_contains($lower, 'on null') && (str_contains($lower, 'call to a member function') || str_contains($lower, 'attempt to read property') || str_contains($lower, 'attempt to assign property'))) {
            return new ErrorExplanation(
                code: 'KGN-ERR-NULL-DEREFERENCE',
                who: $who,
                what: 'Tried to access a method or property on a `null` value.',
                why: 'A lookup (such as a database query `first()`, session lookup, or optional relation) returned `null`, and the next line assumed an object was present.',
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Check for `null` before accessing the object at `%s:%d` (for example, throw `HttpException::notFound()` when a record is missing).', $resolvedFile, $resolvedLine),
                    'Or use PHP\'s null-safe operator `$obj?->property` when `null` is an acceptable outcome.',
                ],
                codeFix: "if (null === \$record) {\n    throw HttpException::notFound('Record not found.');\n}",
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 10. ArgumentCountError (Too Few Arguments)
        if ($exception instanceof ArgumentCountError) {
            return new ErrorExplanation(
                code: 'KGN-ERR-ARG-COUNT',
                who: $who,
                what: 'A function or constructor was called with too few arguments.',
                why: $safeMessage,
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Open `%s:%d` and pass the missing required argument(s) shown in the error message.', $resolvedFile, $resolvedLine),
                    'If this is a controller or service constructor, make sure all dependencies are registered in `app/bootstrap.php`.',
                ],
                command: 'composer analyse',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 11. TypeError (Strict Types Mismatch)
        if ($exception instanceof TypeError) {
            $detail = $this->explainTypeErrorDetail($safeMessage);

            return new ErrorExplanation(
                code: 'KGN-ERR-TYPE-MISMATCH',
                who: $who,
                what: $detail['what'],
                why: $detail['why'],
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Check the value passed at `%s:%d` and convert or type-hint it to match the expected type.', $resolvedFile, $resolvedLine),
                    'Remember Kongono enforces `declare(strict_types=1)`: route/form inputs arrive as strings unless cast (e.g. `(int) $id`) or typed via `{id:int}` / DTO validation.',
                    'Run PHPStan Level 9 to find every type mismatch statically.',
                ],
                command: 'composer analyse',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 12. Database / PDO Errors (Missing Table, Missing Column, Unique Constraint, FK, Connection)
        $isDbMsg = $exception instanceof PDOException
            || str_contains($lower, 'sqlstate[')
            || str_contains($lower, 'no such table')
            || str_contains($lower, 'no such column')
            || (str_contains($lower, 'does not exist') && str_contains($lower, 'relation'))
            || str_contains($lower, 'unique constraint')
            || str_contains($lower, 'duplicate entry')
            || str_contains($lower, 'could not find driver');

        if ($isDbMsg) {
            return $this->explainDatabaseError($safeMessage, $lower, $where, $when, $kongoBin, $resolvedFile, $resolvedLine);
        }

        // 13. Container / Dependency Injection Resolution Failure
        if (str_contains($lower, 'not bound') || str_contains($lower, 'cannot resolve') || str_contains($lower, 'unresolvable')) {
            $service = $this->extractQuoted($safeMessage) ?? 'YourServiceInterface';

            return new ErrorExplanation(
                code: 'KGN-ERR-DI-UNBOUND',
                who: 'Kongono Service Container (PSR-11)',
                what: sprintf('Service or interface `%s` is not registered in the container.', $service),
                why: 'Kongono avoids hidden global magic: interfaces and services with scalar constructor arguments must be explicitly wired in `app/bootstrap.php`.',
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Register `%s` in `app/bootstrap.php` using `$app->instance(...)` or `$app->container()->singleton(...)`.', $service),
                    'Inspect your full dependency wiring with `kongo graph`.',
                ],
                codeFix: sprintf('$app->container()->singleton(%s::class, static fn() => new ConcreteImpl(...));', $this->shortClass($service)),
                command: $kongoBin . ' graph',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 14. Missing / Invalid APP_KEY
        if (str_contains($lower, 'app_key') || str_contains($lower, 'encryption key') || str_contains($lower, '32 bytes')) {
            return new ErrorExplanation(
                code: 'KGN-ERR-APP-KEY',
                who: 'Kongono Security / Encryption Layer',
                what: 'Your application signing/encryption key (`APP_KEY`) is missing or too short.',
                why: 'Sessions, CSRF tokens, signed links, and encrypted vaults require a strong 256-bit `APP_KEY` in `.env`.',
                where: $where,
                when: $when,
                howToFix: [
                    'Generate a cryptographically secure 256-bit key and store it in `.env` as `APP_KEY=...`.',
                    'Restart the dev server after updating `.env`.',
                ],
                command: $kongoBin . ' key:generate',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 15. Missing AI Provider Configuration
        if (str_contains($lower, 'no ai provider configured')) {
            return new ErrorExplanation(
                code: 'KGN-ERR-AI-PROVIDER',
                who: 'Kongono AI Layer (Oshie / Chie / Hantei)',
                what: 'No AI provider credentials are configured in `.env`.',
                why: 'Kongono does not lock you to one vendor, so it needs at least one provider key (OpenAI, Anthropic, Gemini, Groq) or a local Ollama URL.',
                where: $where,
                when: $when,
                howToFix: [
                    'Set `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `OLLAMA_HOST=http://127.0.0.1:11434` in `.env`.',
                    'Run `kongo doctor` to verify connectivity.',
                ],
                command: $kongoBin . ' doctor',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 16. Generic ParseError in regular PHP file
        if ($exception instanceof ParseError) {
            return new ErrorExplanation(
                code: 'KGN-ERR-PHP-SYNTAX',
                who: sprintf('PHP 8.5 Parser (%s)', $resolvedFile),
                what: sprintf('PHP syntax error on line %d of `%s`.', $resolvedLine, $resolvedFile),
                why: $safeMessage,
                where: $where,
                when: $when,
                howToFix: [
                    sprintf('Inspect line %d (and the line immediately above it) in `%s` for a missing semicolon `;`, bracket `}`, parenthesis `)`, or quote.', $resolvedLine, $resolvedFile),
                    sprintf('Verify syntax quickly with `php -l %s`.', $resolvedFile),
                ],
                command: sprintf('php -l %s', $resolvedFile),
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        // 16b. Unwrap generic wrapper exceptions (`RuntimeException`, `CoreException`) to explain the root cause
        if (null !== $exception->getPrevious()) {
            $prevExp = $this->explainThrowable(
                exception: $exception->getPrevious(),
                method: $method,
                path: $path,
                basePath: $basePath,
                kongoBin: $kongoBin,
                availableRoutes: $availableRoutes,
                timestampUtc: $timestampUtc,
            );
            if ('high' === $prevExp->confidence) {
                return $prevExp;
            }
        }

        // 17. Fallback — Still clear 5W1H with actionable Hantei / stack guidance
        $isRuntimeError = $exception instanceof Error;

        return new ErrorExplanation(
            code: $isRuntimeError ? 'KGN-ERR-PHP-ERROR' : 'KGN-ERR-UNHANDLED-EXCEPTION',
            who: $who,
            what: '' !== $safeMessage
                ? sprintf('%s: %s', $this->shortClass($exception::class), $safeMessage)
                : sprintf('Unhandled `%s` was thrown.', $this->shortClass($exception::class)),
            why: sprintf('An unhandled `%s` interrupted execution at `%s:%d` and was not caught by your controller or middleware.', $exception::class, $resolvedFile, $resolvedLine),
            where: $where,
            when: $when,
            howToFix: [
                sprintf('Inspect the highlighted line at `%s:%d` in the stack viewer below.', $resolvedFile, $resolvedLine),
                'Check the Request and Previous Exception tabs to see the exact inputs that triggered this failure.',
                'Click "Diagnose Live with Hantei" or copy the LLM Packet to generate a targeted patch and regression test.',
            ],
            command: $kongoBin . ' check',
            didYouMean: [] !== $availableRoutes && null !== $path ? $this->suggestSimilarRoutes($method ?? 'GET', $path, $availableRoutes) : [],
            sourceFile: $resolvedFile,
            sourceLine: $resolvedLine,
            confidence: 'medium',
        );
    }

    /**
     * Explain HTTP 4xx/5xx framework responses (404 Route Not Found, 405 Method Not Allowed,
     * 403 CSRF / Forbidden, 401 Unauthorized, 422 Validation, 429 Rate Limit) in plain 5W1H English.
     *
     * @param list<string>                $availableRoutes Registered route signatures like `GET /dashboard`
     * @param array<string, list<string>> $validationErrors
     */
    public function explainHttpStatus(
        int $statusCode,
        string $message,
        string $method,
        string $path,
        array $availableRoutes = [],
        array $validationErrors = [],
        string $kongoBin = 'php vendor/bin/kongo',
        ?string $timestampUtc = null,
    ): ErrorExplanation {
        $safeMsg = SecretScrubber::scrub($message);
        $safePath = SecretScrubber::scrub($path);
        $upperMethod = strtoupper($method);
        $where = sprintf('%s %s', $upperMethod, $safePath);
        $when = $this->formatWhen($upperMethod, $safePath, $timestampUtc);
        $lower = strtolower($safeMsg);

        // 404 Not Found — smart route matcher (method mismatch + Levenshtein "Did you mean?")
        if (404 === $statusCode) {
            $samePathMethods = $this->findMethodsForSamePath($safePath, $availableRoutes);
            $similarRoutes = $this->suggestSimilarRoutes($upperMethod, $safePath, $availableRoutes);

            if ([] !== $samePathMethods) {
                return new ErrorExplanation(
                    code: 'KGN-HTTP-404-METHOD-MISMATCH',
                    who: 'Kongono Router (HTTP Dispatch)',
                    what: sprintf('Path `%s` exists, but it does not accept `%s` requests.', $safePath, $upperMethod),
                    why: sprintf('Your app sent `%s %s`, while this path is only registered for: %s.', $upperMethod, $safePath, implode(', ', $samePathMethods)),
                    where: $where,
                    when: $when,
                    howToFix: [
                        sprintf('Change your request/form method to `%s`, OR add `#[%s(\'%s\')]` on your controller method.', $samePathMethods[0], ucfirst(strtolower($upperMethod)), $safePath),
                        'Inspect all registered routes with `kongo routes`.',
                    ],
                    command: $kongoBin . ' routes',
                    didYouMean: array_map(static fn(string $m): string => $m . ' ' . $safePath, $samePathMethods),
                );
            }

            return new ErrorExplanation(
                code: 'KGN-HTTP-404-ROUTE-NOT-FOUND',
                who: 'Kongono Router (HTTP Dispatch)',
                what: sprintf('No route matches `%s %s`.', $upperMethod, $safePath),
                why: [] !== $similarRoutes
                    ? sprintf('`%s %s` is not registered. It looks very close to `%s`.', $upperMethod, $safePath, $similarRoutes[0])
                    : sprintf('None of your registered controllers handle `%s %s` (or the controller was not registered via `$app->controller(...)` in `app/bootstrap.php`).', $upperMethod, $safePath),
                where: $where,
                when: $when,
                howToFix: [
                    [] !== $similarRoutes
                        ? sprintf('Check for a typo — did you mean `%s`?', $similarRoutes[0])
                        : sprintf('Add a `#[%s(\'%s\')]` route attribute to a controller method and register the controller with `$app->controller(MyController::class)`.', ucfirst(strtolower($upperMethod)), $safePath),
                    'List every active route in your app with `kongo routes`.',
                ],
                command: $kongoBin . ' routes',
                didYouMean: $similarRoutes,
            );
        }

        // 405 Method Not Allowed
        if (405 === $statusCode) {
            $samePathMethods = $this->findMethodsForSamePath($safePath, $availableRoutes);

            return new ErrorExplanation(
                code: 'KGN-HTTP-405-METHOD-NOT-ALLOWED',
                who: 'Kongono Router (HTTP Method Guard)',
                what: sprintf('HTTP method `%s` is not allowed on `%s`.', $upperMethod, $safePath),
                why: [] !== $samePathMethods
                    ? sprintf('Route `%s` only accepts: %s.', $safePath, implode(', ', $samePathMethods))
                    : 'The endpoint exists, but only for a different HTTP verb (e.g. POST instead of GET).',
                where: $where,
                when: $when,
                howToFix: [
                    [] !== $samePathMethods
                        ? sprintf('Use `%s %s`, or add a `#[%s(\'%s\')]` handler on your controller.', $samePathMethods[0], $safePath, ucfirst(strtolower($upperMethod)), $safePath)
                        : 'Update the link/form/fetch method to match the route attribute on your controller.',
                ],
                command: $kongoBin . ' routes',
                didYouMean: array_map(static fn(string $m): string => $m . ' ' . $safePath, $samePathMethods),
            );
        }

        // 403 CSRF Token Mismatch / Missing
        if (403 === $statusCode && str_contains($lower, 'csrf')) {
            return new ErrorExplanation(
                code: 'KGN-HTTP-403-CSRF',
                who: 'Kongono CsrfMiddleware (Security Layer)',
                what: sprintf('`%s %s` was blocked because the CSRF token was missing or did not match your session.', $upperMethod, $safePath),
                why: 'Every state-changing browser request (`POST`, `PUT`, `PATCH`, `DELETE`) requires a signed `_csrf` form field (or `X-CSRF-Token` header) paired with an active session cookie.',
                where: $where,
                when: $when,
                howToFix: [
                    'Add `<input type="hidden" name="_csrf" value="{{ $csrf }}">` inside your HTML `<form>` (note: the field name is `_csrf`, not `_token`).',
                    'For JavaScript `fetch()` calls, send the `X-CSRF-Token` header with the same token.',
                    'If this is a stateless external webhook (like Stripe), add its path prefix to `exemptPrefixes` on `CsrfMiddleware` and verify its webhook signature instead.',
                ],
                codeFix: "<form method=\"POST\" action=\"{$safePath}\">\n  <input type=\"hidden\" name=\"_csrf\" value=\"{{ \$csrf }}\">\n  ...\n</form>",
            );
        }

        // 401 Unauthorized
        if (401 === $statusCode) {
            return new ErrorExplanation(
                code: 'KGN-HTTP-401-UNAUTHORIZED',
                who: 'Authentication Middleware / Guard',
                what: sprintf('Authentication is required to access `%s %s`.', $upperMethod, $safePath),
                why: '' !== $safeMsg ? $safeMsg : 'No valid session cookie or Bearer token was attached to this request.',
                where: $where,
                when: $when,
                howToFix: [
                    'Sign in first so your browser holds an active session cookie, or pass `Authorization: Bearer <token>` for API requests.',
                    'If this route should be public, remove the auth middleware/attribute from its controller method.',
                ],
            );
        }

        // 422 Validation Failed
        if (422 === $statusCode) {
            $fieldSummary = [];
            foreach ($validationErrors as $field => $errs) {
                $fieldSummary[] = sprintf('`%s`: %s', $field, implode('; ', $errs));
            }

            return new ErrorExplanation(
                code: 'KGN-HTTP-422-VALIDATION',
                who: 'Kongono Validator (Request Input Validation)',
                what: sprintf('Input validation failed for `%s %s` (%d field%s).', $upperMethod, $safePath, count($validationErrors), 1 === count($validationErrors) ? '' : 's'),
                why: [] !== $fieldSummary
                    ? 'The submitted fields failed validation rules: ' . implode(' | ', $fieldSummary)
                    : ('' !== $safeMsg ? $safeMsg : 'One or more submitted fields did not satisfy the controller DTO validation rules.'),
                where: $where,
                when: $when,
                howToFix: [
                    'Correct the highlighted fields in your form or JSON payload to satisfy the DTO attributes.',
                    'Ensure your HTML input `name="..."` attributes exactly match the DTO property names.',
                ],
            );
        }

        // 429 Rate Limited
        if (429 === $statusCode) {
            return new ErrorExplanation(
                code: 'KGN-HTTP-429-RATE-LIMIT',
                who: 'Kongono RateLimitMiddleware (Abuse Protection)',
                what: sprintf('Too many requests sent to `%s %s`.', $upperMethod, $safePath),
                why: 'This client exceeded the configured request quota for the current window.',
                where: $where,
                when: $when,
                howToFix: [
                    'Wait for the `Retry-After` window to reset before retrying.',
                    'If testing locally, raise `maxRequests` on `RateLimitMiddleware` in `app/bootstrap.php` or clear local cache.',
                ],
                command: $kongoBin . ' cache:clear',
            );
        }

        return new ErrorExplanation(
            code: sprintf('KGN-HTTP-%d', $statusCode),
            who: 'Kongono HTTP Pipeline',
            what: '' !== $safeMsg ? $safeMsg : sprintf('Request failed with HTTP %d.', $statusCode),
            why: sprintf('A route or middleware returned HTTP %d while handling `%s %s`.', $statusCode, $upperMethod, $safePath),
            where: $where,
            when: $when,
            howToFix: [
                'Inspect the response headers, middleware order in `app/bootstrap.php`, and the handler for this route.',
            ],
            confidence: 'medium',
        );
    }

    /**
     * Extracts original `.kgn.html` template source path embedded by `ViewEngine` in compiled PHP view cache files.
     *
     * @return array{template_name: string, template_path: string}|null
     */
    public function resolveCompiledViewSource(string $compiledFile): ?array
    {
        if (!is_file($compiledFile) || !is_readable($compiledFile)) {
            return null;
        }
        $handle = @fopen($compiledFile, 'rb');
        if (false === $handle) {
            return null;
        }
        $head = (string) fread($handle, 512);
        fclose($handle);

        if (1 === preg_match('#//\s*@kongono-source:\s*([^\s(]+)\s*\(([^)]+)\)#', $head, $m)) {
            return [
                'template_name' => trim($m[1]),
                'template_path' => trim($m[2]),
            ];
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function suggestSimilarMethods(string $fqcn, string $badMethod): array
    {
        if (!class_exists($fqcn) && !interface_exists($fqcn)) {
            return [];
        }

        $ref = new ReflectionClass($fqcn);
        $scored = [];
        $needle = strtolower($badMethod);

        foreach ($ref->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            $name = $method->getName();
            if (str_starts_with($name, '__')) {
                continue;
            }
            $dist = self::boundedLevenshtein($needle, strtolower($name));
            $maxDist = max(2, (int) floor(strlen($needle) / 2));
            if ($dist <= $maxDist) {
                $scored[$name] = $dist;
            }
        }

        asort($scored);

        return array_slice(array_keys($scored), 0, 3);
    }

    /**
     * @param list<string> $availableRoutes
     * @return list<string>
     */
    private function findMethodsForSamePath(string $path, array $availableRoutes): array
    {
        $normPath = '/' . trim($path, '/');
        $methods = [];

        foreach ($availableRoutes as $sig) {
            $parts = explode(' ', trim($sig), 2);
            if (2 !== count($parts)) {
                continue;
            }
            $routePath = '/' . trim($parts[1], '/');
            if ($routePath === $normPath) {
                $methods[$parts[0]] = true;
            }
        }

        return array_keys($methods);
    }

    /**
     * @param list<string> $availableRoutes
     * @return list<string>
     */
    private function suggestSimilarRoutes(string $method, string $path, array $availableRoutes): array
    {
        $normPath = '/' . trim($path, '/');
        $scored = [];

        foreach ($availableRoutes as $sig) {
            $parts = explode(' ', trim($sig), 2);
            if (2 !== count($parts)) {
                continue;
            }
            $rMethod = strtoupper($parts[0]);
            $rPath = '/' . trim($parts[1], '/');
            $dist = self::boundedLevenshtein(strtolower($normPath), strtolower($rPath));
            $penalty = $rMethod === $method ? 0 : 1;
            $maxDist = max(3, (int) floor(strlen($normPath) * 0.45));
            if ($dist <= $maxDist) {
                $scored[$sig] = ($dist * 10) + $penalty;
            }
        }

        asort($scored);

        return array_slice(array_keys($scored), 0, 3);
    }

    /**
     * @return list<string>
     */
    private function suggestSimilarViews(string $missingView, string $basePath): array
    {
        $viewsRoot = rtrim($basePath, '\\/') . DIRECTORY_SEPARATOR . 'views';
        if (!is_dir($viewsRoot)) {
            return [];
        }

        $scored = [];
        $needle = strtolower(trim($missingView, '/'));
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($viewsRoot, \FilesystemIterator::SKIP_DOTS),
        );

        foreach ($it as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                continue;
            }
            $full = str_replace('\\', '/', $file->getPathname());
            $prefix = str_replace('\\', '/', $viewsRoot) . '/';
            if (!str_starts_with($full, $prefix) || !str_ends_with($full, '.kgn.html')) {
                continue;
            }
            $logical = substr($full, strlen($prefix), -strlen('.kgn.html'));
            $dist = self::boundedLevenshtein($needle, strtolower($logical));
            if ($dist <= max(3, (int) floor(strlen($needle) * 0.45))) {
                $scored[$logical] = $dist;
            }
        }

        asort($scored);

        return array_slice(array_keys($scored), 0, 3);
    }

    private static function boundedLevenshtein(string $a, string $b): int
    {
        if (strlen($a) > 255 || strlen($b) > 255) {
            return PHP_INT_MAX;
        }
        $dist = levenshtein($a, $b);

        return $dist >= 0 ? $dist : PHP_INT_MAX;
    }

    private function explainDatabaseError(
        string $safeMessage,
        string $lower,
        string $where,
        string $when,
        string $kongoBin,
        string $resolvedFile,
        int $resolvedLine,
    ): ErrorExplanation {
        if (str_contains($lower, 'no such table') || (str_contains($lower, 'does not exist') && str_contains($lower, 'relation')) || str_contains($lower, 'sqlstate[42p01]') || str_contains($lower, 'sqlstate[42s02]')) {
            return new ErrorExplanation(
                code: 'KGN-ERR-DB-NO-TABLE',
                who: 'Database Layer (PDO / SQL)',
                what: 'Missing Database Table — your SQL query referenced a table that does not exist yet.',
                why: $safeMessage,
                where: $where,
                when: $when,
                howToFix: [
                    'Run pending database migrations so all tables are created.',
                    'Verify `DATABASE_URL` in `.env` points to the right database.',
                ],
                command: $kongoBin . ' migrate',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        if (str_contains($lower, 'no such column') || str_contains($lower, 'sqlstate[42703]') || str_contains($lower, 'sqlstate[42s22]') || str_contains($lower, 'unknown column')) {
            return new ErrorExplanation(
                code: 'KGN-ERR-DB-NO-COLUMN',
                who: 'Database Layer (PDO / SQL)',
                what: 'Your SQL query referenced a column name that does not exist on that table.',
                why: $safeMessage,
                where: $where,
                when: $when,
                howToFix: [
                    'Check the column spelling in your SQL query against your latest migration file.',
                    'If you added a new column recently, run `kongo migrate` to apply the schema change.',
                ],
                command: $kongoBin . ' migrate',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        if (str_contains($lower, 'unique constraint') || str_contains($lower, 'duplicate entry') || str_contains($lower, 'sqlstate[23505]') || str_contains($lower, 'sqlstate[23000]')) {
            return new ErrorExplanation(
                code: 'KGN-ERR-DB-UNIQUE',
                who: 'Database Layer (Unique Constraint)',
                what: 'Tried to insert or update a duplicate value in a column marked UNIQUE.',
                why: $safeMessage,
                where: $where,
                when: $when,
                howToFix: [
                    'Check if the record (such as an email or slug) already exists before inserting, and return a friendly 422 validation error.',
                    'Or use an `ON CONFLICT ... DO UPDATE` (upsert) query if updating existing rows is intended.',
                ],
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        if (str_contains($lower, 'could not find driver')) {
            return new ErrorExplanation(
                code: 'KGN-ERR-DB-DRIVER',
                who: 'PHP PDO Extension',
                what: 'The required PHP PDO database driver extension is not enabled.',
                why: $safeMessage,
                where: $where,
                when: $when,
                howToFix: [
                    'Enable `extension=pdo_sqlite` (for SQLite) or `extension=pdo_pgsql` (for PostgreSQL) in your `php.ini`.',
                    'Run `php -m` to confirm the driver appears, then restart your dev server.',
                ],
                command: 'php -m',
                sourceFile: $resolvedFile,
                sourceLine: $resolvedLine,
            );
        }

        return new ErrorExplanation(
            code: 'KGN-ERR-DB-QUERY',
            who: 'Database Layer (PDO / SQL)',
            what: 'A database connection or SQL query failed.',
            why: $safeMessage,
            where: $where,
            when: $when,
            howToFix: [
                'Verify your database server is running and `DATABASE_URL` in `.env` is reachable.',
                'Inspect the highlighted query line and ensure all bound parameters match placeholders.',
            ],
            command: $kongoBin . ' doctor',
            sourceFile: $resolvedFile,
            sourceLine: $resolvedLine,
        );
    }

    /**
     * @return array{what: string, why: string}
     */
    private function explainTypeErrorDetail(string $safeMessage): array
    {
        if (1 === preg_match('/Argument #(\d+) \(\$([^)]+)\) must be of type ([^,]+), ([^ ]+) given/', $safeMessage, $tm)) {
            return [
                'what' => sprintf('Wrong type passed to parameter `$%s`: expected `%s`, got `%s`.', $tm[2], $tm[3], $tm[4]),
                'why' => sprintf('Because Kongono uses strict PHP 8.5 types (`declare(strict_types=1)`), PHP refused to silently coerce `%s` into `%s` for argument #%s (`$%s`).', $tm[4], $tm[3], $tm[1], $tm[2]),
            ];
        }

        if (1 === preg_match('/Return value must be of type ([^,]+), ([^ ]+) returned/', $safeMessage, $rm)) {
            return [
                'what' => sprintf('Function returned `%s` instead of the declared return type `%s`.', $rm[2], $rm[1]),
                'why' => sprintf('The method signature promises `%s`, so returning `%s` triggered a strict `TypeError`.', $rm[1], $rm[2]),
            ];
        }

        return [
            'what' => 'A strict PHP 8.5 type mismatch occurred.',
            'why' => $safeMessage,
        ];
    }

    private function inferWho(Throwable $exception, string $resolvedFile, bool $isCompiledView): string
    {
        if ($isCompiledView) {
            return sprintf('View Template (%s)', $resolvedFile);
        }
        if ($exception instanceof PDOException) {
            return 'Database Layer (PDO / SQL)';
        }
        $fqcn = $exception::class;
        if (str_starts_with($fqcn, 'Kongono\\View\\')) {
            return 'Kongono ViewEngine';
        }
        if (str_starts_with($fqcn, 'Kongono\\Security\\')) {
            return 'Kongono Security Layer';
        }
        if (str_starts_with($fqcn, 'Kongono\\Database\\')) {
            return 'Kongono Database Layer';
        }
        if (str_starts_with($fqcn, 'Kongono\\Http\\')) {
            return 'Kongono HTTP Layer';
        }
        if (str_starts_with($fqcn, 'Kongono\\Core\\')) {
            return 'Kongono Core Container / Kernel';
        }

        return sprintf('Application Code (%s)', basename($resolvedFile));
    }

    private function formatWhen(?string $method, ?string $path, ?string $timestampUtc): string
    {
        $ts = $timestampUtc ?? gmdate('Y-m-d\TH:i:s\Z');
        if (null !== $method && null !== $path) {
            return sprintf('During HTTP %s %s at %s', strtoupper($method), SecretScrubber::scrub($path), $ts);
        }

        return sprintf('During PHP execution at %s', $ts);
    }

    private function routeSuffix(?string $method, ?string $path): string
    {
        if (null === $method || null === $path) {
            return '';
        }

        return sprintf(' while handling %s %s', strtoupper($method), SecretScrubber::scrub($path));
    }

    private function extractQuoted(string $text): ?string
    {
        if (1 === preg_match('/["\']([^"\']+)["\']/', $text, $m)) {
            return $m[1];
        }

        return null;
    }

    private function extractCommand(string $text): ?string
    {
        if (1 === preg_match('/`((?:php\s+[^\s`]*(?:kongo|zokeibi)|composer)\s+[^`]+)`/i', $text, $m)) {
            return trim($m[1]);
        }

        return null;
    }

    private function relativePath(string $path, ?string $basePath): string
    {
        $normalized = str_replace('\\', '/', $path);
        if (null !== $basePath && '' !== $basePath) {
            $base = rtrim(str_replace('\\', '/', $basePath), '/') . '/';
            if (str_starts_with($normalized, $base)) {
                return substr($normalized, strlen($base));
            }
        }

        return $normalized;
    }

    private function shortClass(string $fqcn): string
    {
        $pos = strrpos($fqcn, '\\');

        return false === $pos ? $fqcn : substr($fqcn, $pos + 1);
    }
}
