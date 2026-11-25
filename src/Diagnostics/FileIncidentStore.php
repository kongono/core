<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/**
 * Bounded, traversal-safe local JSON store for sanitized Kongono incidents (`storage/incidents/<KGN-...>.json`).
 */
final readonly class FileIncidentStore implements IncidentStoreInterface
{
    private const string REF_PATTERN = '/\AKGN-\d{8}-[A-F0-9]{8}\z/';

    public function __construct(
        private string $directory,
        private int $maxRecords = 200,
    ) {}

    public function record(IncidentRecord $incident): void
    {
        if (1 !== preg_match(self::REF_PATTERN, $incident->reference)) {
            return;
        }
        if (!is_dir($this->directory)) {
            @mkdir($this->directory, 0o750, true);
        }

        $path = $this->directory . DIRECTORY_SEPARATOR . $incident->reference . '.json';
        if (is_link($path)) {
            return;
        }
        $json = json_encode($incident->toArray(), JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $tmp = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
        $handle = @fopen($tmp, 'xb');
        if (false !== $handle) {
            @chmod($tmp, 0o600);
            $written = @fwrite($handle, $json);
            @fclose($handle);
            if (false !== $written && $written === strlen($json)) {
                if (!@rename($tmp, $path)) {
                    @unlink($path);
                    if (!@rename($tmp, $path)) {
                        @unlink($tmp);
                    }
                }
            } else {
                @unlink($tmp);
            }
        }

        $this->pruneOldest();
    }

    public function find(string $reference): ?IncidentRecord
    {
        $normalized = strtoupper(trim($reference));
        if (1 !== preg_match(self::REF_PATTERN, $normalized)) {
            return null;
        }

        $path = $this->directory . DIRECTORY_SEPARATOR . $normalized . '.json';
        if (!is_file($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        if (false === $raw) {
            return null;
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return null;
        }

        /** @var array<string, mixed> $decoded */
        return IncidentRecord::fromArray($decoded);
    }

    public function recent(int $limit = 20): array
    {
        if (!is_dir($this->directory)) {
            return [];
        }
        $files = glob($this->directory . DIRECTORY_SEPARATOR . 'KGN-*.json');
        if (false === $files || [] === $files) {
            return [];
        }

        $mtimes = [];
        foreach ($files as $file) {
            $mt = @filemtime($file);
            $mtimes[$file] = false !== $mt ? $mt : 0;
        }
        usort($files, static fn(string $a, string $b): int => $mtimes[$b] <=> $mtimes[$a]);
        $records = [];
        foreach (array_slice($files, 0, max(1, $limit)) as $file) {
            $raw = @file_get_contents($file);
            if (false === $raw) {
                continue;
            }
            $decoded = json_decode($raw, true);
            if (!is_array($decoded)) {
                continue;
            }
            /** @var array<string, mixed> $decoded */
            $records[] = IncidentRecord::fromArray($decoded);
        }

        return $records;
    }

    private function pruneOldest(): void
    {
        if ($this->maxRecords <= 0 || !is_dir($this->directory)) {
            return;
        }
        $files = glob($this->directory . DIRECTORY_SEPARATOR . 'KGN-*.json');
        if (false === $files || count($files) <= $this->maxRecords) {
            return;
        }
        $mtimes = [];
        foreach ($files as $file) {
            $mt = @filemtime($file);
            $mtimes[$file] = false !== $mt ? $mt : 0;
        }
        usort($files, static fn(string $a, string $b): int => $mtimes[$b] <=> $mtimes[$a]);
        foreach (array_slice($files, $this->maxRecords) as $stale) {
            @unlink($stale);
        }
    }
}
