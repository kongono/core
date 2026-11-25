<?php

declare(strict_types=1);

namespace Kongono\Core\Events;

use Closure;
use Fiber;
use Kongono\Core\CoreException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\EventDispatcher\StoppableEventInterface;
use WeakMap;

/** Synchronous, ordered, Fiber-aware reentrancy-safe PSR-14 event dispatcher. */
final class EventDispatcher implements EventDispatcherInterface
{
    /** @var array<class-string, list<Closure(object): void>> */
    private array $listeners = [];

    private bool $rootDispatching = false;

    /** @var ?WeakMap<object, bool> */
    private ?WeakMap $fiberDispatching = null;

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
        $fiber = Fiber::getCurrent();
        if (null !== $fiber) {
            if (null === $this->fiberDispatching) {
                /** @var WeakMap<object, bool> $map */
                $map = new WeakMap();
                $this->fiberDispatching = $map;
            }
            if (true === ($this->fiberDispatching[$fiber] ?? false)) {
                throw new CoreException('Reentrant event dispatch on the same EventDispatcher instance is not permitted.');
            }
            $this->fiberDispatching[$fiber] = true;
        } else {
            if ($this->rootDispatching) {
                throw new CoreException('Reentrant event dispatch on the same EventDispatcher instance is not permitted.');
            }
            $this->rootDispatching = true;
        }

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
            if (null !== $fiber && null !== $this->fiberDispatching) {
                unset($this->fiberDispatching[$fiber]);
            } else {
                $this->rootDispatching = false;
            }
        }
    }
}
