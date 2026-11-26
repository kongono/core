<?php

declare(strict_types=1);

namespace Kongono\Core\Tests;

use PHPUnit\Framework\TestCase;

final class StandalonePackageManifestTest extends TestCase
{
    public function testAllPackageManifestsAreValidAcyclicAndPhp8513Hardened(): void
    {
        $repoRoot = dirname(__DIR__, 3);
        $manifests = glob($repoRoot . '/packages/*/composer.json');
        self::assertIsArray($manifests);
        self::assertCount(11, $manifests);

        /** @var array<string, list<string>> $graph */
        $graph = [];

        foreach ($manifests as $path) {
            $raw = file_get_contents($path);
            self::assertIsString($raw, "Unable to read {$path}");
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
            $name = $decoded['name'] ?? '';
            self::assertIsString($name);
            self::assertStringStartsWith('kongono/', $name);
            self::assertSame('MIT', $decoded['license'] ?? null, "{$name} must declare MIT license");
            self::assertIsArray($decoded['require'] ?? null);
            self::assertSame('>=8.5.13', $decoded['require']['php'] ?? null, "{$name} must enforce php >= 8.5.13");
            self::assertIsArray($decoded['autoload']['psr-4'] ?? null);

            $internalDeps = [];
            foreach (array_keys($decoded['require']) as $dep) {
                if (is_string($dep) && str_starts_with($dep, 'kongono/')) {
                    $internalDeps[] = $dep;
                }
            }
            $graph[$name] = $internalDeps;
        }

        // Verify strictly acyclic dependency graph (zero circular Composer requires across all 11 packages)
        $state = [];
        $visit = static function (string $node) use (&$visit, &$state, $graph): void {
            if (($state[$node] ?? 0) === 1) {
                self::fail("Circular Composer dependency detected involving {$node}.");
            }
            if (($state[$node] ?? 0) === 2) {
                return;
            }
            $state[$node] = 1;
            foreach ($graph[$node] ?? [] as $dep) {
                $visit($dep);
            }
            $state[$node] = 2;
        };

        foreach (array_keys($graph) as $pkg) {
            $visit($pkg);
        }

        // Verify standalone split packages have minimal, lean require sets + README.md + LICENSE
        self::assertSame([], $graph['kongono/core']);
        self::assertSame(['kongono/core'], $graph['kongono/validation']);
        self::assertSame(['kongono/core'], $graph['kongono/security']);
        self::assertSame(['kongono/core', 'kongono/validation'], $graph['kongono/ai']);

        foreach (['core', 'validation', 'security', 'ai'] as $splitPkg) {
            self::assertFileExists($repoRoot . "/packages/{$splitPkg}/README.md");
            self::assertFileExists($repoRoot . "/packages/{$splitPkg}/LICENSE");
            self::assertFileExists($repoRoot . "/packages/{$splitPkg}/composer.json");
        }
    }
}
