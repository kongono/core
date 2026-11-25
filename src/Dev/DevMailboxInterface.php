<?php

declare(strict_types=1);

namespace Kongono\Core\Dev;

/**
 * Storage contract for Kongono's built-in Dev Mailbox (`/_kongono` Mailbox tab).
 * Captures rendered outgoing emails locally without requiring SMTP, Docker, or Mailpit.
 */
interface DevMailboxInterface
{
    /**
     * @param array{
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
     * } $message
     */
    public function append(array $message): void;

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
    public function messages(): array;

    public function clear(): void;
}
