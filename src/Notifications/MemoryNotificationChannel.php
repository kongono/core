<?php

declare(strict_types=1);

namespace Kongono\Core\Notifications;

/** In-memory notification channel for fast deterministic unit and integration testing. */
final class MemoryNotificationChannel implements NotificationChannelInterface
{
    /** @var list<array{recipient: array<string, mixed>, notification: Notification}> */
    private array $sent = [];

    public function __construct(
        private readonly string $channelName = 'memory',
    ) {}

    public function name(): string
    {
        return $this->channelName;
    }

    public function send(array $recipient, Notification $notification): void
    {
        $this->sent[] = ['recipient' => $recipient, 'notification' => $notification];
    }

    /** @return list<array{recipient: array<string, mixed>, notification: Notification}> */
    public function sent(): array
    {
        return $this->sent;
    }

    public function clear(): void
    {
        $this->sent = [];
    }
}
