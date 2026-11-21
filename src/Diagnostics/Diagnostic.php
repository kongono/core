<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/** Structured, disclosure-classified diagnostic record. */
final readonly class Diagnostic
{
    /**
     * @param array<string, array{value: string|int|bool, disclosure: Disclosure}> $fields
     */
    public function __construct(
        public string $id,
        public string $title,
        public string $remediation,
        public array $fields = [],
    ) {}

    /** Return only Safe fields, suitable for public display or AI debugging context. */
    /** @return array<string, string|int|bool> */
    public function safeFields(): array
    {
        $safe = [];
        foreach ($this->fields as $key => $entry) {
            if (Disclosure::Safe === $entry['disclosure']) {
                $safe[$key] = is_string($entry['value'])
                    ? SecretScrubber::scrub($entry['value'])
                    : $entry['value'];
            }
        }

        return $safe;
    }

    /** @return array{id: string, title: string, remediation: string, fields: array<string, string|int|bool>} */
    public function toSafeArray(): array
    {
        return [
            'id' => $this->id,
            'title' => $this->title,
            'remediation' => $this->remediation,
            'fields' => $this->safeFields(),
        ];
    }
}
