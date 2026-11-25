<?php

declare(strict_types=1);

namespace Kongono\Core\Async;

use Closure;
use Fiber;
use InvalidArgumentException;
use Throwable;

/**
 * Cooperative PHP 8.5 Fiber concurrency primitives for persistent-runtime apps.
 *
 * Enables interleaving I/O-bound tasks (parallel API calls, queue polling, streaming reads)
 * cleanly inside a single request scope with zero static/global mutable state.
 */
final readonly class Async
{
    /**
     * Execute an associative or indexed map of closures concurrently via PHP Fibers
     * and return their results preserving exact keys and order.
     *
     * @template TKey of array-key
     * @template TVal
     * @param array<TKey, Closure(): TVal> $tasks
     * @return array<TKey, TVal>
     */
    public static function all(array $tasks): array
    {
        if ([] === $tasks) {
            return [];
        }

        $parentCaps = \Kongono\Core\Capabilities\ExecutionCapabilities::current();

        /** @var array<TKey, Fiber<mixed, mixed, TVal, mixed>> $fibers */
        $fibers = [];
        /** @var array<TKey, TVal> $results */
        $results = [];

        foreach ($tasks as $key => $task) {
            $wrapped = null !== $parentCaps
                ? static fn(): mixed => \Kongono\Core\Capabilities\ExecutionCapabilities::withActive($parentCaps, $task)
                : $task;
            /** @var Fiber<mixed, mixed, TVal, mixed> $fiber */
            $fiber = new Fiber($wrapped);
            $fibers[$key] = $fiber;
        }

        foreach ($fibers as $key => $fiber) {
            $fiber->start();
            if ($fiber->isTerminated()) {
                $results[$key] = $fiber->getReturn();
            }
        }

        while (count($results) < count($fibers)) {
            $progressed = false;
            foreach ($fibers as $key => $fiber) {
                if (array_key_exists($key, $results)) {
                    continue;
                }
                if ($fiber->isSuspended()) {
                    $fiber->resume();
                    $progressed = true;
                }
                if ($fiber->isTerminated()) {
                    $results[$key] = $fiber->getReturn();
                    $progressed = true;
                }
            }
            if (!$progressed) {
                break;
            }
        }

        /** @var array<TKey, TVal> $ordered */
        $ordered = [];
        foreach (array_keys($tasks) as $key) {
            $ordered[$key] = $results[$key];
        }

        return $ordered;
    }

    /**
     * Run cooperative Fibers and return the value of the first task to complete.
     *
     * @template TVal
     * @param non-empty-array<array-key, Closure(): TVal> $tasks
     * @return TVal
     */
    public static function race(array $tasks): mixed
    {
        $parentCaps = \Kongono\Core\Capabilities\ExecutionCapabilities::current();

        /** @var list<Fiber<mixed, mixed, TVal, mixed>> $fibers */
        $fibers = [];
        foreach ($tasks as $task) {
            $wrapped = null !== $parentCaps
                ? static fn(): mixed => \Kongono\Core\Capabilities\ExecutionCapabilities::withActive($parentCaps, $task)
                : $task;
            /** @var Fiber<mixed, mixed, TVal, mixed> $fiber */
            $fiber = new Fiber($wrapped);
            $fibers[] = $fiber;
        }

        foreach ($fibers as $fiber) {
            $fiber->start();
            if ($fiber->isTerminated()) {
                return $fiber->getReturn();
            }
        }

        while (true) {
            $anyActive = false;
            foreach ($fibers as $fiber) {
                if ($fiber->isSuspended()) {
                    $anyActive = true;
                    $fiber->resume();
                    if ($fiber->isTerminated()) {
                        return $fiber->getReturn();
                    }
                }
            }
            if (!$anyActive) {
                throw new InvalidArgumentException('Async::race() did not resolve any task.');
            }
        }
    }

    /**
     * Concurrently map an array of items through a closure using PHP Fibers, preserving keys.
     *
     * @template TKey of array-key
     * @template TIn
     * @template TOut
     * @param array<TKey, TIn>             $items
     * @param Closure(TIn, TKey): TOut     $mapper
     * @return array<TKey, TOut>
     */
    public static function map(array $items, Closure $mapper): array
    {
        /** @var array<TKey, Closure(): TOut> $tasks */
        $tasks = [];
        foreach ($items as $key => $item) {
            $tasks[$key] = static fn() => $mapper($item, $key);
        }

        return self::all($tasks);
    }

    /**
     * Cooperatively yield control back to the scheduler when executing inside a Fiber.
     * Safe no-op when invoked outside of a Fiber context.
     */
    public static function suspend(mixed $value = null): mixed
    {
        if (null !== Fiber::getCurrent()) {
            return Fiber::suspend($value);
        }

        return $value;
    }

    /**
     * Execute tasks concurrently and settle each into ['ok' => true, 'value' => ...]
     * or ['ok' => false, 'error' => Throwable] without aborting siblings on failure.
     *
     * @template TKey of array-key
     * @template TItem
     * @param array<TKey, Closure(): TItem> $tasks
     * @return array<TKey, array{ok: true, value: TItem}|array{ok: false, error: Throwable}>
     */
    public static function allSettled(array $tasks): array
    {
        /** @var array<TKey, Closure(): (array{ok: true, value: TItem}|array{ok: false, error: Throwable})> $wrapped */
        $wrapped = [];
        foreach ($tasks as $key => $task) {
            $wrapped[$key] = static function () use ($task): array {
                try {
                    return ['ok' => true, 'value' => $task()];
                } catch (Throwable $e) {
                    return ['ok' => false, 'error' => $e];
                }
            };
        }

        return self::all($wrapped);
    }
}
