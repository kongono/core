<?php

declare(strict_types=1);

namespace Kongono\Core\Capabilities;

use Closure;
use Fiber;
use Kongono\Core\Diagnostics\SecretScrubber;
use WeakMap;

/**
 * Per-operation-scope least-privilege capability sandbox (`#[ReadOnlyDb]`, `#[NoOutboundHttp]`,
 * `#[MaxQueries]`, `#[MaxAiCost]`). Scoped per Fiber/execution frame with deterministic `finally`
 * cleanup — completely persistent-runtime safe.
 */
final class ExecutionCapabilities
{
    /** @var list<self> */
    private static array $rootStack = [];

    /** @var ?WeakMap<object, list<self>> */
    private static ?WeakMap $fiberStacks = null;

    private static int $rootRlsSetConfigDepth = 0;

    /** @var ?WeakMap<object, int> */
    private static ?WeakMap $fiberRlsSetConfigDepth = null;

    /** @var array<string, true> */
    private const array SAFE_LEADING_KEYWORDS = [
        'SELECT' => true,
        'WITH' => true,
        'SHOW' => true,
        'DESCRIBE' => true,
        'DESC' => true,
        'EXPLAIN' => true,
        'VALUES' => true,
        'PRAGMA' => true,
    ];

    /** @var array<string, true> */
    private const array SAFE_READ_PRAGMAS = [
        'TABLE_INFO' => true,
        'TABLE_XINFO' => true,
        'INDEX_LIST' => true,
        'INDEX_INFO' => true,
        'INDEX_XINFO' => true,
        'FOREIGN_KEY_LIST' => true,
        'DATABASE_LIST' => true,
        'COMPILE_OPTIONS' => true,
        'INTEGRITY_CHECK' => true,
        'QUICK_CHECK' => true,
        'USER_VERSION' => true,
        'SCHEMA_VERSION' => true,
        'APPLICATION_ID' => true,
        'PAGE_COUNT' => true,
        'PAGE_SIZE' => true,
        'FREELIST_COUNT' => true,
    ];

    /** @var array<string, true> */
    private const array ALWAYS_MUTATING_KEYWORDS = [
        'INSERT' => true,
        'UPDATE' => true,
        'DELETE' => true,
        'REPLACE' => true,
        'DROP' => true,
        'ALTER' => true,
        'TRUNCATE' => true,
        'CREATE' => true,
        'GRANT' => true,
        'REVOKE' => true,
        'MERGE' => true,
        'UPSERT' => true,
        'VACUUM' => true,
        'ATTACH' => true,
        'DETACH' => true,
        'LOCK' => true,
        'UNLOCK' => true,
        'CALL' => true,
        'COPY' => true,
        'EXECUTE' => true,
        'PREPARE' => true,
        'DEALLOCATE' => true,
        'LOAD' => true,
        'RENAME' => true,
        'REINDEX' => true,
        'CLUSTER' => true,
        'REFRESH' => true,
        'CHECKPOINT' => true,
        'LISTEN' => true,
        'UNLISTEN' => true,
        'NOTIFY' => true,
        'IMPORT' => true,
        'EXPORT' => true,
        'FLUSH' => true,
        'KILL' => true,
        'PURGE' => true,
        'REPAIR' => true,
        'OPTIMIZE' => true,
        'INSTALL' => true,
        'UNINSTALL' => true,
        'SHUTDOWN' => true,
        'RESTART' => true,
        'BINLOG' => true,
        'HANDLER' => true,
        'REASSIGN' => true,
        'INTO' => true,
    ];

    /** @var array<string, true> */
    private const array MUTATING_SYSTEM_FUNCTIONS = [
        'SET_CONFIG' => true,
        'PG_TERMINATE_BACKEND' => true,
        'PG_CANCEL_BACKEND' => true,
        'PG_NOTIFY' => true,
        'LO_IMPORT' => true,
        'LO_EXPORT' => true,
        'LO_CREATE' => true,
        'LO_UNLINK' => true,
        'LO_PUT' => true,
        'LO_FROM_BYTEA' => true,
        'LO_OPEN' => true,
        'LO_WRITE' => true,
        'LO_TRUNCATE' => true,
        'LO_TRUNCATE64' => true,
        'LO_LSEEK' => true,
        'LO_LSEEK64' => true,
        'PG_FILE_WRITE' => true,
        'PG_FILE_UNLINK' => true,
        'PG_READ_FILE' => true,
        'PG_READ_BINARY_FILE' => true,
        'PG_LS_DIR' => true,
        'PG_STAT_FILE' => true,
        'LOAD_FILE' => true,
        'PG_RELOAD_CONF' => true,
        'PG_ROTATE_LOGFILE' => true,
        'PG_SWITCH_WAL' => true,
        'PG_STAT_RESET' => true,
        'PG_CREATE_RESTORE_POINT' => true,
        'PG_CREATE_PHYSICAL_REPLICATION_SLOT' => true,
        'PG_CREATE_LOGICAL_REPLICATION_SLOT' => true,
        'PG_DROP_REPLICATION_SLOT' => true,
        'PG_LOGICAL_EMIT_MESSAGE' => true,
        'PG_PROMOTE' => true,
        'NEXTVAL' => true,
        'SETVAL' => true,
        'PG_ADVISORY_LOCK' => true,
        'PG_ADVISORY_XACT_LOCK' => true,
        'PG_TRY_ADVISORY_LOCK' => true,
        'PG_TRY_ADVISORY_XACT_LOCK' => true,
        'PG_ADVISORY_LOCK_SHARED' => true,
        'PG_ADVISORY_XACT_LOCK_SHARED' => true,
        'PG_TRY_ADVISORY_LOCK_SHARED' => true,
        'PG_TRY_ADVISORY_XACT_LOCK_SHARED' => true,
        'PG_ADVISORY_UNLOCK' => true,
        'PG_ADVISORY_UNLOCK_SHARED' => true,
        'PG_ADVISORY_UNLOCK_ALL' => true,
        'GET_LOCK' => true,
        'RELEASE_LOCK' => true,
        'DBLINK' => true,
        'DBLINK_CONNECT' => true,
        'DBLINK_EXEC' => true,
        'DBLINK_SEND_QUERY' => true,
    ];

    private int $queryCount = 0;
    private float $aiSpendUsd = 0.0;
    private ?self $parent = null;

    public function __construct(
        public readonly bool $readOnlyDb = false,
        public readonly bool $noOutboundHttp = false,
        public readonly ?int $maxQueries = null,
        public readonly ?float $maxAiCostUsd = null,
    ) {}

    /**
     * Return a fresh per-request copy of this policy with zeroed query/AI counters
     * (prevents persistent-worker state leaks across requests).
     */
    public function fresh(): self
    {
        return new self(
            readOnlyDb: $this->readOnlyDb,
            noOutboundHttp: $this->noOutboundHttp,
            maxQueries: $this->maxQueries,
            maxAiCostUsd: $this->maxAiCostUsd,
        );
    }

    /**
     * Narrowly allow PostgreSQL `RowLevelSecurity::withTenant()`'s own transaction-local
     * `SELECT set_config(?, ?, true)` call under `#[ReadOnlyDb]` without weakening user SQL guards.
     *
     * @internal
     * @template T
     * @param Closure(): T $callback
     * @return T
     */
    public static function withAllowedRlsSetConfig(Closure $callback): mixed
    {
        $fiber = Fiber::getCurrent();
        if (null !== $fiber) {
            if (null === self::$fiberRlsSetConfigDepth) {
                /** @var WeakMap<object, int> $map */
                $map = new WeakMap();
                self::$fiberRlsSetConfigDepth = $map;
            }
            $prev = self::$fiberRlsSetConfigDepth[$fiber] ?? 0;
            self::$fiberRlsSetConfigDepth[$fiber] = $prev + 1;

            try {
                return $callback();
            } finally {
                if (null !== self::$fiberRlsSetConfigDepth) {
                    if (0 === $prev) {
                        unset(self::$fiberRlsSetConfigDepth[$fiber]);
                    } else {
                        self::$fiberRlsSetConfigDepth[$fiber] = $prev;
                    }
                }
            }
        }

        ++self::$rootRlsSetConfigDepth;

        try {
            return $callback();
        } finally {
            --self::$rootRlsSetConfigDepth;
        }
    }

    private static function isRlsSetConfigAllowed(): bool
    {
        $fiber = Fiber::getCurrent();
        if (null !== $fiber && null !== self::$fiberRlsSetConfigDepth && (self::$fiberRlsSetConfigDepth[$fiber] ?? 0) > 0) {
            return true;
        }

        return self::$rootRlsSetConfigDepth > 0;
    }

    /**
     * Return the active `ExecutionCapabilities` for the current Fiber / request frame, if any.
     * Inherits from running ancestor Fibers while staying strictly isolated from suspended sibling Fibers.
     */
    public static function current(): ?self
    {
        $fiber = Fiber::getCurrent();
        if (null !== $fiber) {
            if (null !== self::$fiberStacks) {
                if (isset(self::$fiberStacks[$fiber]) && [] !== self::$fiberStacks[$fiber]) {
                    $stack = self::$fiberStacks[$fiber];

                    return $stack[count($stack) - 1];
                }
                // Walk active running ancestor Fibers (suspended sibling Fibers have isRunning() === false)
                $ancestor = null;
                foreach (self::$fiberStacks as $candidateFiber => $stack) {
                    if ($candidateFiber instanceof Fiber && $candidateFiber->isRunning() && [] !== $stack) {
                        $ancestor = $stack[count($stack) - 1];
                    }
                }
                if (null !== $ancestor) {
                    return $ancestor;
                }
            }

            return [] !== self::$rootStack ? self::$rootStack[count(self::$rootStack) - 1] : null;
        }

        return [] !== self::$rootStack ? self::$rootStack[count(self::$rootStack) - 1] : null;
    }

    /**
     * Execute `$callback` with `$capabilities` active in the current Fiber / request frame.
     *
     * @template T
     * @param Closure(): T $callback
     * @return T
     */
    public static function withActive(self $capabilities, Closure $callback): mixed
    {
        $outer = self::current();
        $effective = (null !== $outer && $outer !== $capabilities && !$capabilities->hasAncestor($outer))
            ? $outer->merge($capabilities)
            : $capabilities;

        $fiber = Fiber::getCurrent();
        if (null !== $fiber) {
            if (null === self::$fiberStacks) {
                /** @var WeakMap<object, list<self>> $map */
                $map = new WeakMap();
                self::$fiberStacks = $map;
            }
            $stack = self::$fiberStacks[$fiber] ?? [];
            $stack[] = $effective;
            self::$fiberStacks[$fiber] = $stack;

            try {
                return $callback();
            } finally {
                if (null !== self::$fiberStacks) {
                    $cur = self::$fiberStacks[$fiber] ?? [];
                    array_pop($cur);
                    if ([] === $cur) {
                        unset(self::$fiberStacks[$fiber]);
                    } else {
                        self::$fiberStacks[$fiber] = $cur;
                    }
                }
            }
        }

        self::$rootStack[] = $effective;

        try {
            return $callback();
        } finally {
            array_pop(self::$rootStack);
        }
    }

    private function hasAncestor(self $candidate): bool
    {
        $cur = $this->parent;
        while (null !== $cur) {
            if ($cur === $candidate) {
                return true;
            }
            $cur = $cur->parent;
        }

        return false;
    }

    /**
     * Combine two capability policies into their strictest (least-privilege) intersection.
     */
    public function merge(self $other): self
    {
        $maxQ = null;
        if (null !== $this->maxQueries && null !== $other->maxQueries) {
            $maxQ = min($this->maxQueries, $other->maxQueries);
        } elseif (null !== $this->maxQueries) {
            $maxQ = $this->maxQueries;
        } elseif (null !== $other->maxQueries) {
            $maxQ = $other->maxQueries;
        }

        $maxCost = null;
        if (null !== $this->maxAiCostUsd && null !== $other->maxAiCostUsd) {
            $maxCost = min($this->maxAiCostUsd, $other->maxAiCostUsd);
        } elseif (null !== $this->maxAiCostUsd) {
            $maxCost = $this->maxAiCostUsd;
        } elseif (null !== $other->maxAiCostUsd) {
            $maxCost = $other->maxAiCostUsd;
        }

        $merged = new self(
            readOnlyDb: $this->readOnlyDb || $other->readOnlyDb,
            noOutboundHttp: $this->noOutboundHttp || $other->noOutboundHttp,
            maxQueries: $maxQ,
            maxAiCostUsd: $maxCost,
        );
        $merged->parent = $this;

        return $merged;
    }

    /**
     * Enforces `#[ReadOnlyDb]` and `#[MaxQueries]` BEFORE a SQL statement reaches the database driver.
     */
    public function assertDbQueryAllowed(string $sql): void
    {
        $this->parent?->assertDbQueryAllowed($sql);

        if (
            $this->readOnlyDb
            && !(self::isRlsSetConfigAllowed() && 'SELECT set_config(?, ?, true)' === trim($sql))
            && self::isWriteSql($sql)
        ) {
            $snippet = SecretScrubber::scrub(substr(trim((string) preg_replace('/\s+/', ' ', $sql)), 0, 120));

            throw new CapabilityException(
                capability: '#[ReadOnlyDb]',
                message: sprintf('#[ReadOnlyDb] blocked mutating SQL statement before execution: "%s".', $snippet),
            );
        }

        ++$this->queryCount;
        if (null !== $this->maxQueries && $this->queryCount > $this->maxQueries) {
            throw new CapabilityException(
                capability: sprintf('#[MaxQueries(%d)]', $this->maxQueries),
                message: sprintf(
                    '#[MaxQueries(%d)] budget exceeded on query #%d. Use BatchLoader or a JOIN to reduce query count.',
                    $this->maxQueries,
                    $this->queryCount,
                ),
            );
        }
    }

    /**
     * Enforces `#[NoOutboundHttp]` BEFORE DNS resolution or opening any outbound socket.
     */
    public function assertOutboundHttpAllowed(string $url): void
    {
        if ($this->noOutboundHttp) {
            $safeUrl = SecretScrubber::scrub(substr($url, 0, 160));

            throw new CapabilityException(
                capability: '#[NoOutboundHttp]',
                message: sprintf('#[NoOutboundHttp] blocked outbound HTTP request to "%s".', $safeUrl),
            );
        }
    }

    /**
     * Enforces `#[MaxAiCost]` budget for AI calls made inside this request scope (propagating to outer scopes).
     */
    public function recordAiSpend(float $costUsd): void
    {
        $this->parent?->recordAiSpend($costUsd);
        if ($costUsd > 0.0) {
            $this->aiSpendUsd += $costUsd;
        }
        if (null !== $this->maxAiCostUsd && $this->aiSpendUsd > $this->maxAiCostUsd) {
            throw new CapabilityException(
                capability: sprintf('#[MaxAiCost(%.4f)]', $this->maxAiCostUsd),
                message: sprintf(
                    '#[MaxAiCost(%.4f)] AI spend cap exceeded (cumulative: $%.4f USD).',
                    $this->maxAiCostUsd,
                    $this->aiSpendUsd,
                ),
            );
        }
    }

    public function queryCount(): int
    {
        return $this->queryCount;
    }

    public function aiSpendUsd(): float
    {
        return $this->aiSpendUsd;
    }

    /**
     * Strict allowlist + fail-closed single-pass SQL lexer that blocks write/DDL/DCL/stacked/mutating
     * statements and cross-dialect lexer ambiguities (`\'` backslash-quote desyncs, `#` operators/comments,
     * nested `/*` block comments, unclosed literals/dollar-quotes, quoted/commented system function calls,
     * parenthesized mutating PRAGMAs, `EXPLAIN ANALYZE`, `INTO`, `FOR UPDATE/SHARE`, and MySQL `/*!...`).
     */
    public static function isWriteSql(string $sql): bool
    {
        $len = strlen($sql);
        $i = 0;
        /** @var list<string> $words */
        $words = [];
        /** @var list<string> $tokens */
        $tokens = [];
        $sawSemicolon = false;
        $hasEquals = false;
        $hasParen = false;
        /** @var list<string> $functionCalls */
        $functionCalls = [];

        while ($i < $len) {
            $ch = $sql[$i];

            // Skip whitespace (including vertical tab and form feed)
            if (' ' === $ch || "\t" === $ch || "\n" === $ch || "\r" === $ch || "\f" === $ch || "\v" === $ch) {
                ++$i;
                continue;
            }

            // `#` is a MySQL line comment AND a PostgreSQL operator — fail closed to prevent dialect desync
            if ('#' === $ch) {
                return true;
            }

            // Line comment `--`: only treat as comment when followed by whitespace/control/EOF (MySQL rule)
            // and stop on EITHER `\n` OR `\r` (PostgreSQL rule)
            if ('-' === $ch && $i + 1 < $len && '-' === $sql[$i + 1]) {
                $afterDash = $i + 2 < $len ? $sql[$i + 2] : '';
                if ('' === $afterDash || ' ' === $afterDash || "\t" === $afterDash || "\n" === $afterDash || "\r" === $afterDash || "\f" === $afterDash || "\v" === $afterDash) {
                    $i += 2;
                    $i += strcspn($sql, "\r\n", $i);
                    continue;
                }
                // `--` not followed by whitespace (e.g. MySQL `--1`): do NOT skip the line
                $i += 2;
                continue;
            }

            // Block comments: `/* ... */` (fail closed on nested `/*` or unclosed comments; lex MySQL `/*!...` interior)
            if ('/' === $ch && $i + 1 < $len && '*' === $sql[$i + 1]) {
                if ($i + 2 < $len && '!' === $sql[$i + 2]) {
                    $i += 3;
                    while ($i < $len && ctype_digit($sql[$i])) {
                        ++$i;
                    }
                    continue;
                }
                $i += 2;
                $closed = false;
                while ($i < $len) {
                    if ('/' === $sql[$i] && $i + 1 < $len && '*' === $sql[$i + 1]) {
                        // Nested block comment desyncs PostgreSQL vs MySQL/SQLite -> fail closed
                        return true;
                    }
                    if ('*' === $sql[$i] && $i + 1 < $len && '/' === $sql[$i + 1]) {
                        $i += 2;
                        $closed = true;
                        break;
                    }
                    ++$i;
                }
                if (!$closed) {
                    return true;
                }
                continue;
            }

            // Ignore closing `*/` left over from MySQL conditional comments `/*!...*/`
            if ('*' === $ch && $i + 1 < $len && '/' === $sql[$i + 1]) {
                $i += 2;
                continue;
            }

            // Reject stacked statements (any SQL token after `;`)
            if ($sawSemicolon) {
                return true;
            }

            // Single-quoted string literal: fail closed on backslash escapes (dialect differential) or unclosed quotes
            if ("'" === $ch) {
                ++$i;
                $closed = false;
                while ($i < $len) {
                    if ('\\' === $sql[$i]) {
                        return true;
                    }
                    if ("'" === $sql[$i]) {
                        if ($i + 1 < $len && "'" === $sql[$i + 1]) {
                            $i += 2;
                            continue;
                        }
                        ++$i;
                        $closed = true;
                        break;
                    }
                    ++$i;
                }
                if (!$closed) {
                    return true;
                }
                $tokens[] = '<STR>';
                continue;
            }

            // Double-quoted or backtick-quoted identifier: fail closed on backslash inside `"` or unclosed quote,
            // and still detect quoted function calls like `"pg_terminate_backend"(123)`
            if ('"' === $ch || '`' === $ch) {
                $quote = $ch;
                ++$i;
                $ident = '';
                $closed = false;
                while ($i < $len) {
                    if ('"' === $quote && '\\' === $sql[$i]) {
                        return true;
                    }
                    if ($quote === $sql[$i]) {
                        if ($i + 1 < $len && $quote === $sql[$i + 1]) {
                            $ident .= $quote;
                            $i += 2;
                            continue;
                        }
                        ++$i;
                        $closed = true;
                        break;
                    }
                    $ident .= $sql[$i];
                    ++$i;
                }
                if (!$closed) {
                    return true;
                }
                if ('' !== $ident) {
                    $upperIdent = strtoupper($ident);
                    $tokens[] = $upperIdent;
                    if (self::isFollowedByOpenParen($sql, $i, $len)) {
                        $functionCalls[] = $upperIdent;
                    }
                }
                continue;
            }

            // Dollar-quoted `$tag$...$tag$` is dialect-ambiguous across MySQL/SQLite vs Postgres -> fail closed
            if ('$' === $ch) {
                $endTag = $i + 1;
                while ($endTag < $len && (ctype_alnum($sql[$endTag]) || '_' === $sql[$endTag])) {
                    ++$endTag;
                }
                if ($endTag < $len && '$' === $sql[$endTag]) {
                    return true;
                }
            }

            // PostgreSQL Unicode-escaped identifiers/strings (`U&"..."` / `U&'...'` + `UESCAPE`) -> fail closed
            if (('U' === $ch || 'u' === $ch) && $i + 1 < $len && '&' === $sql[$i + 1]) {
                return true;
            }

            if (';' === $ch) {
                $sawSemicolon = true;
                ++$i;
                continue;
            }

            if ('=' === $ch) {
                $hasEquals = true;
                $tokens[] = '=';
                ++$i;
                continue;
            }

            if ('(' === $ch) {
                $hasParen = true;
                $tokens[] = '(';
                ++$i;
                continue;
            }

            if (')' === $ch || '.' === $ch || ',' === $ch) {
                $tokens[] = $ch;
                ++$i;
                continue;
            }

            // Unquoted ASCII identifier / SQL keyword
            if (ctype_alpha($ch) || '_' === $ch) {
                $start = $i;
                ++$i;
                while ($i < $len && (ctype_alnum($sql[$i]) || '_' === $sql[$i])) {
                    ++$i;
                }
                $word = strtoupper(substr($sql, $start, $i - $start));
                if ('UESCAPE' === $word) {
                    return true;
                }
                $words[] = $word;
                $tokens[] = $word;

                if (self::isFollowedByOpenParen($sql, $i, $len)) {
                    $functionCalls[] = $word;
                }
                continue;
            }

            $tokens[] = $ch;
            ++$i;
        }

        if ([] === $words) {
            return false;
        }

        $first = $words[0];
        if (!isset(self::SAFE_LEADING_KEYWORDS[$first])) {
            return true;
        }

        // Strict read-only PRAGMA grammar: `PRAGMA [schema.]<safe_pragma>[ ( <ident> ) ]`
        // Blocks `PRAGMA writable_schema = ON`, `PRAGMA foreign_keys(0)`, `PRAGMA foreign_keys(table_info)`, etc.
        if ('PRAGMA' === $first) {
            if ($hasEquals || count($tokens) < 2) {
                return true;
            }
            $pos = 1;
            $tokCount = count($tokens);
            // Optional `schema.` prefix (only when explicitly separated by `.`)
            if ($pos + 2 < $tokCount && '.' === $tokens[$pos + 1]) {
                $pos += 2;
            }
            $pragmaName = $tokens[$pos] ?? '';
            if (!isset(self::SAFE_READ_PRAGMAS[$pragmaName])) {
                return true;
            }
            ++$pos;
            if ($pos === $tokCount) {
                return false;
            }
            // Only specific table/index introspection PRAGMAs may take a single `(ident|string)` argument
            $argToken = $tokens[$pos + 1] ?? '';
            if (
                !in_array($pragmaName, ['TABLE_INFO', 'TABLE_XINFO', 'INDEX_LIST', 'INDEX_INFO', 'INDEX_XINFO', 'FOREIGN_KEY_LIST'], true)
                || $tokCount !== $pos + 3
                || '(' !== $tokens[$pos]
                || ')' !== $tokens[$pos + 2]
                || in_array($argToken, ['', '(', ')', ',', '=', '.'], true)
            ) {
                return true;
            }

            return false;
        }

        $wordCount = count($words);
        for ($idx = 0; $idx < $wordCount; ++$idx) {
            $w = $words[$idx];
            if (isset(self::ALWAYS_MUTATING_KEYWORDS[$w])) {
                return true;
            }
            if ('EXPLAIN' === $first && 'ANALYZE' === $w) {
                return true;
            }
            if ('FOR' === $w && $idx + 1 < $wordCount) {
                $next = $words[$idx + 1];
                if ('SHARE' === $next || 'NO' === $next || 'KEY' === $next) {
                    return true;
                }
            }
        }

        foreach ($functionCalls as $fn) {
            if (isset(self::MUTATING_SYSTEM_FUNCTIONS[$fn])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if `$pos` is followed by `(`, skipping whitespace and inline SQL comments (`/* ...` / `-- ...`).
     */
    private static function isFollowedByOpenParen(string $sql, int $pos, int $len): bool
    {
        $look = $pos;
        while ($look < $len) {
            $c = $sql[$look];
            if (' ' === $c || "\t" === $c || "\n" === $c || "\r" === $c || "\f" === $c || "\v" === $c) {
                ++$look;
                continue;
            }
            if ('/' === $c && $look + 1 < $len && '*' === $sql[$look + 1]) {
                $end = strpos($sql, '*/', $look + 2);
                if (false === $end) {
                    return true; // Fail closed on unclosed comment after identifier
                }
                $look = $end + 2;
                continue;
            }
            if ('-' === $c && $look + 1 < $len && '-' === $sql[$look + 1]) {
                $look += 2;
                $look += strcspn($sql, "\r\n", $look);
                continue;
            }

            return '(' === $c;
        }

        return false;
    }
}
