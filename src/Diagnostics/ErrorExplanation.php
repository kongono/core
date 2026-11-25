<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/**
 * Structured, secret-scrubbed 5W1H (Who, What, Why, Where, When, How to Fix) error explanation
 * designed for both human developers (plain everyday language) and AI agents (machine-readable contract).
 */
final readonly class ErrorExplanation
{
    /**
     * @param list<string> $howToFix
     * @param list<string> $didYouMean
     */
    public function __construct(
        public string $code,
        public string $who,
        public string $what,
        public string $why,
        public string $where,
        public string $when,
        public array $howToFix,
        public ?string $codeFix = null,
        public ?string $command = null,
        public array $didYouMean = [],
        public ?string $sourceFile = null,
        public ?int $sourceLine = null,
        public string $confidence = 'high',
    ) {}

    /**
     * Secret-scrubbed array suitable for JSON dev responses, CLI output, and AI tool calls.
     *
     * @return array{
     *     code: string,
     *     confidence: string,
     *     who: string,
     *     what: string,
     *     why: string,
     *     where: string,
     *     when: string,
     *     how_to_fix: list<string>,
     *     code_fix: ?string,
     *     command: ?string,
     *     did_you_mean: list<string>,
     *     source_file: ?string,
     *     source_line: ?int
     * }
     */
    public function toArray(): array
    {
        return [
            'code' => $this->code,
            'confidence' => $this->confidence,
            'who' => SecretScrubber::scrub($this->who),
            'what' => SecretScrubber::scrub($this->what),
            'why' => SecretScrubber::scrub($this->why),
            'where' => SecretScrubber::scrub($this->where),
            'when' => SecretScrubber::scrub($this->when),
            'how_to_fix' => array_map(static fn(string $step): string => SecretScrubber::scrub($step), $this->howToFix),
            'code_fix' => null !== $this->codeFix ? SecretScrubber::scrub($this->codeFix) : null,
            'command' => null !== $this->command ? SecretScrubber::scrub($this->command) : null,
            'did_you_mean' => array_map(static fn(string $item): string => SecretScrubber::scrub($item), $this->didYouMean),
            'source_file' => null !== $this->sourceFile ? SecretScrubber::scrub($this->sourceFile) : null,
            'source_line' => $this->sourceLine,
        ];
    }

    /**
     * Secret-scrubbed Markdown summary for LLM / AI coding agents and CLI terminals.
     */
    public function toMarkdown(): string
    {
        $safe = $this->toArray();
        $lines = [
            sprintf('## Plain-English Diagnosis (`%s`)', $safe['code']),
            sprintf('- **Who:** %s', $safe['who']),
            sprintf('- **What:** %s', $safe['what']),
            sprintf('- **Why:** %s', $safe['why']),
            sprintf('- **Where:** %s', $safe['where']),
            sprintf('- **When:** %s', $safe['when']),
        ];

        if ([] !== $safe['did_you_mean']) {
            $lines[] = sprintf('- **Did you mean:** %s', implode(', ', array_map(static fn(string $s): string => '`' . $s . '`', $safe['did_you_mean'])));
        }

        if ([] !== $safe['how_to_fix']) {
            $lines[] = '';
            $lines[] = '### How to Fix';
            foreach ($safe['how_to_fix'] as $idx => $step) {
                $lines[] = sprintf('%d. %s', $idx + 1, $step);
            }
        }

        if (null !== $safe['command'] && '' !== $safe['command']) {
            $lines[] = '';
            $lines[] = sprintf('```bash%s%s%s```', "\n", $safe['command'], "\n");
        }

        if (null !== $safe['code_fix'] && '' !== $safe['code_fix']) {
            $lines[] = '';
            $lines[] = sprintf('```php%s%s%s```', "\n", $safe['code_fix'], "\n");
        }

        return implode("\n", $lines);
    }
}
