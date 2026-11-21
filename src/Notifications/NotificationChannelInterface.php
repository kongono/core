<?php

declare(strict_types=1);

namespace Kongono\Core\Notifications;

/** Delivery channel contract (email, Slack/webhook, SMS, database, in-memory). */
interface NotificationChannelInterface
{
    public function name(): string;

    /**
     * Deliver a notification to one recipient identifier (e.g. email address, user ID, webhook URL).
     *
     * @param array<string, mixed> $recipient
     */
    public function send(array $recipient, Notification $notification): void;
}
