<?php

declare(strict_types=1);

namespace Kongono\Core\Notifications;

/** Immutable multi-channel notification envelope. */
final readonly class Notification
{
    /** @param array<string, mixed> $data */
    public function __construct(
        public string $type,
        public string $subject,
        public string $body,
        public array $data = [],
    ) {}
}
