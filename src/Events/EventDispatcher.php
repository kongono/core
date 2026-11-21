<?php

declare(strict_types=1);

namespace Kongono\Core\Events;

use Closure;
use Kongono\Core\CoreException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\EventDispatcher\StoppableEventInterface;

/** Synchronous, ordered, reentrancy-safe PSR-14 event dispatcher. */
final class EventDispatcher implements EventDispatcherInterface
{
    /** @var array<class-string, list<Closure(object): void>> */
    private array $listeners = [];

    private bool $dispatching = false;

    /**
     * @template T of object
     * @param class-string<T> $eventClass
     * @param Closure(T): void $listener
     */
    public function listen(string $eventClass, Closure $listener): self
    {
        /** @var Closure(object): void $typed */
        $typed = $listener;
        $this->listeners[$eventClass][] = $typed;

        return $this;
    }

    public function dispatch(object $event): object
    {
        if ($this->dispatching) {
            throw new CoreException('Reentrant event dispatch on the same EventDispatcher instance is not permitted.');
        }

        $this->dispatching = true;

        try {
            $class = $event::class;
            foreach ($this->listeners[$class] ?? [] as $listener) {
                if ($event instanceof StoppableEventInterface && $event->isPropagationStopped()) {
                    break;
                }
                $listener($event);
            }

            return $event;
        } finally {
            $this->dispatching = false;
        }
    }
}
