<?php

declare(strict_types=1);

namespace Kongono\Core\Notifications;

use Kongono\Core\Diagnostics\SecretScrubber;
use Throwable;

/**
 * Multi-channel Notification Dispatcher delivering one Notification across registered
 * channels (mail, webhook, memory, etc.) with isolated per-channel error reporting.
 */
final class NotificationDispatcher
{
    /** @var array<string, NotificationChannelInterface> */
    private array $channels = [];

    public function registerChannel(NotificationChannelInterface $channel): self
    {
        $this->channels[$channel->name()] = $channel;

        return $this;
    }

    /**
     * Send a notification across the requested channel names (or all registered channels if empty).
     *
     * @param array<string, mixed> $recipient
     * @param list<string>         $channels
     * @return array<string, array{ok: bool, error?: string}>
     */
    public function send(array $recipient, Notification $notification, array $channels = []): array
    {
        $targets = [] !== $channels ? $channels : array_keys($this->channels);
        $results = [];

        foreach ($targets as $channelName) {
            if (!isset($this->channels[$channelName])) {
                $results[$channelName] = [
                    'ok' => false,
                    'error' => sprintf('Unknown notification channel "%s".', $channelName),
                ];
                continue;
            }

            try {
                $this->channels[$channelName]->send($recipient, $notification);
                $results[$channelName] = ['ok' => true];
            } catch (Throwable $e) {
                $results[$channelName] = [
                    'ok' => false,
                    'error' => SecretScrubber::scrub($e->getMessage()),
                ];
            }
        }

        return $results;
    }
}
