<?php

declare(strict_types=1);

namespace Kongono\Core\Dev;

use Kongono\Core\Diagnostics\SecretScrubber;

/**
 * Bounded, persistent-runtime-safe JSON file store for local Dev Mailbox captures (`storage/dev/mailbox.json`).
 */
final readonly class FileDevMailbox implements DevMailboxInterface
{
    public function __construct(
        private string $filePath,
        private int $maxMessages = 50,
    ) {}

    public function append(array $message): void
    {
        if (is_link($this->filePath)) {
            return;
        }
        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0o700, true);
        }

        $sanitized = [
            'id' => SecretScrubber::scrub($message['id']),
            'sent_at' => $message['sent_at'],
            'from' => SecretScrubber::scrub($message['from']),
            'to' => array_map(static fn(string $s): string => SecretScrubber::scrub($s), $message['to']),
            'cc' => array_map(static fn(string $s): string => SecretScrubber::scrub($s), $message['cc']),
            'bcc' => array_map(static fn(string $s): string => SecretScrubber::scrub($s), $message['bcc']),
            'subject' => SecretScrubber::scrub($message['subject']),
            'html' => null !== $message['html'] ? SecretScrubber::scrub($message['html']) : null,
            'text' => null !== $message['text'] ? SecretScrubber::scrub($message['text']) : null,
            'attachments' => $message['attachments'],
        ];

        $handle = @fopen($this->filePath, 'c+b');
        if (false === $handle) {
            return;
        }

        try {
            @chmod($this->filePath, 0o600);
            if (!flock($handle, LOCK_EX)) {
                return;
            }
            $raw = stream_get_contents($handle);
            $existing = is_string($raw) ? $this->decodeMessages($raw) : [];
            array_unshift($existing, $sanitized);
            $bounded = array_slice($existing, 0, max(1, $this->maxMessages));
            $encoded = json_encode($bounded, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, $encoded);
            fflush($handle);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    public function messages(): array
    {
        if (is_link($this->filePath) || !is_file($this->filePath)) {
            return [];
        }
        $handle = @fopen($this->filePath, 'rb');
        if (false === $handle) {
            return [];
        }
        try {
            flock($handle, LOCK_SH);
            $raw = stream_get_contents($handle);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
        if (!is_string($raw) || '' === trim($raw)) {
            return [];
        }

        return $this->decodeMessages($raw);
    }

    /**
     * @return list<array{
     *     id: string,
     *     sent_at: string,
     *     from: string,
     *     to: list<string>,
     *     cc: list<string>,
     *     bcc: list<string>,
     *     subject: string,
     *     html: ?string,
     *     text: ?string,
     *     attachments: list<array{filename: string, content_type: string, bytes: int}>
     * }>
     */
    private function decodeMessages(string $raw): array
    {
        if ('' === trim($raw)) {
            return [];
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return [];
        }

        $out = [];
        foreach ($decoded as $item) {
            if (!is_array($item) || !is_string($item['id'] ?? null)) {
                continue;
            }
            $attachments = [];
            if (is_array($item['attachments'] ?? null)) {
                foreach ($item['attachments'] as $att) {
                    if (is_array($att) && is_string($att['filename'] ?? null)) {
                        $attachments[] = [
                            'filename' => $att['filename'],
                            'content_type' => is_string($att['content_type'] ?? null) ? $att['content_type'] : 'application/octet-stream',
                            'bytes' => is_int($att['bytes'] ?? null) ? $att['bytes'] : 0,
                        ];
                    }
                }
            }
            $out[] = [
                'id' => $item['id'],
                'sent_at' => is_string($item['sent_at'] ?? null) ? $item['sent_at'] : '',
                'from' => is_string($item['from'] ?? null) ? $item['from'] : '',
                'to' => is_array($item['to'] ?? null) ? array_values(array_filter($item['to'], 'is_string')) : [],
                'cc' => is_array($item['cc'] ?? null) ? array_values(array_filter($item['cc'], 'is_string')) : [],
                'bcc' => is_array($item['bcc'] ?? null) ? array_values(array_filter($item['bcc'], 'is_string')) : [],
                'subject' => is_string($item['subject'] ?? null) ? $item['subject'] : '',
                'html' => is_string($item['html'] ?? null) ? $item['html'] : null,
                'text' => is_string($item['text'] ?? null) ? $item['text'] : null,
                'attachments' => $attachments,
            ];
        }

        return $out;
    }

    public function clear(): void
    {
        if (!is_link($this->filePath) && is_file($this->filePath)) {
            @unlink($this->filePath);
        }
    }
}
