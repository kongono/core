<?php

declare(strict_types=1);

namespace Kongono\Core\I18n;

/** Zero-dependency multi-locale translator with :placeholder interpolation, pluralization, and Accept-Language negotiation. */
final class Translator
{
    /** @var array<string, array<string, string>> */
    private array $catalogs = [];

    public function __construct(
        private readonly string $fallbackLocale = 'en',
    ) {}

    /** @param array<string, string> $messages */
    public function addMessages(string $locale, array $messages): self
    {
        $norm = strtolower($locale);
        $this->catalogs[$norm] = [...($this->catalogs[$norm] ?? []), ...$messages];

        return $this;
    }

    /**
     * Translate a message key with optional `:placeholder` replacements.
     *
     * @param array<string, string|int|float> $params
     */
    public function get(string $key, array $params = [], ?string $locale = null): string
    {
        $loc = strtolower($locale ?? $this->fallbackLocale);
        $template = $this->catalogs[$loc][$key]
            ?? $this->catalogs[explode('-', $loc)[0]][$key]
            ?? $this->catalogs[$this->fallbackLocale][$key]
            ?? $key;

        if ([] === $params) {
            return $template;
        }

        $replacements = [];
        foreach ($params as $name => $val) {
            $replacements[':' . $name] = (string) $val;
        }

        return strtr($template, $replacements);
    }

    /**
     * Pluralize pipe-delimited forms (`one item|:count items` or `none|one|:count items`).
     *
     * @param array<string, string|int|float> $params
     */
    public function choice(string $key, int $count, array $params = [], ?string $locale = null): string
    {
        $raw = $this->get($key, [], $locale);
        $forms = explode('|', $raw);
        if (3 === count($forms)) {
            $selected = 0 === $count ? $forms[0] : (1 === $count ? $forms[1] : $forms[2]);
        } elseif (2 === count($forms)) {
            $selected = 1 === $count ? $forms[0] : $forms[1];
        } else {
            $selected = $raw;
        }

        $params['count'] = $count;
        $replacements = [];
        foreach ($params as $name => $val) {
            $replacements[':' . $name] = (string) $val;
        }

        return strtr($selected, $replacements);
    }

    /** Pick the best supported locale from an HTTP Accept-Language header. */
    public function negotiate(string $acceptLanguage): string
    {
        $supported = array_keys($this->catalogs);
        if ('' === trim($acceptLanguage) || [] === $supported) {
            return $this->fallbackLocale;
        }

        foreach (explode(',', $acceptLanguage) as $part) {
            $tag = strtolower(trim(explode(';', $part, 2)[0]));
            if (in_array($tag, $supported, true)) {
                return $tag;
            }
            $primary = explode('-', $tag)[0];
            if (in_array($primary, $supported, true)) {
                return $primary;
            }
        }

        return $this->fallbackLocale;
    }
}
