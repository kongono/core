<?php

declare(strict_types=1);

namespace Kongono\Core;

use Closure;
use Psr\Container\ContainerInterface;
use ReflectionClass;
use ReflectionNamedType;

/**
 * Explicit, zero-magic PSR-11 dependency injection container with autowiring
 * and persistent-runtime operation-scoped instance reset.
 */
final class Container implements ContainerInterface
{
    /** @var array<string, Closure(self): mixed> */
    private array $factories = [];

    /** @var array<string, 'transient'|'singleton'|'scoped'> */
    private array $lifetimes = [];

    /** @var array<string, mixed> */
    private array $singletons = [];

    /** @var array<string, mixed> */
    private array $scopedInstances = [];

    /** @var array<string, true> */
    private array $resolving = [];

    /** @var array<string, bool> */
    private array $instantiableCache = [];

    /**
     * Compiled per-class constructor wiring plans (populated once per persistent worker).
     *
     * @var array<string, list<array{
     *     name: string,
     *     classType: ?string,
     *     hasDefault: bool,
     *     default: mixed,
     *     allowsNull: bool
     * }>>
     */
    private array $autowirePlans = [];

    /**
     * Bind a transient factory or concrete class to an ID/interface.
     *
     * @param class-string|string $id
     * @param (Closure(self): mixed)|class-string $concrete
     */
    public function bind(string $id, Closure|string $concrete): self
    {
        $this->factories[$id] = is_string($concrete)
            ? static fn(self $c): object => $c->autowire($concrete)
            : $concrete;
        $this->lifetimes[$id] = 'transient';
        unset($this->singletons[$id], $this->scopedInstances[$id]);

        return $this;
    }

    /**
     * Bind an application-lifetime singleton.
     *
     * @param class-string|string $id
     * @param (Closure(self): mixed)|class-string $concrete
     */
    public function singleton(string $id, Closure|string $concrete): self
    {
        $this->factories[$id] = is_string($concrete)
            ? static fn(self $c): object => $c->autowire($concrete)
            : $concrete;
        $this->lifetimes[$id] = 'singleton';
        unset($this->singletons[$id], $this->scopedInstances[$id]);

        return $this;
    }

    /**
     * Bind an operation-scoped service (cleared automatically between requests in persistent runtimes).
     *
     * @param class-string|string $id
     * @param (Closure(self): mixed)|class-string $concrete
     */
    public function scoped(string $id, Closure|string $concrete): self
    {
        $this->factories[$id] = is_string($concrete)
            ? static fn(self $c): object => $c->autowire($concrete)
            : $concrete;
        $this->lifetimes[$id] = 'scoped';
        unset($this->singletons[$id], $this->scopedInstances[$id]);

        return $this;
    }

    /** Register a pre-built singleton instance. */
    public function instance(string $id, mixed $value): self
    {
        $this->singletons[$id] = $value;
        $this->lifetimes[$id] = 'singleton';
        unset($this->factories[$id], $this->scopedInstances[$id]);

        return $this;
    }

    /** O(1) check whether an explicit binding, singleton, or scoped instance is registered (zero reflection, zero sort). */
    public function hasBinding(string $id): bool
    {
        return array_key_exists($id, $this->singletons)
            || array_key_exists($id, $this->scopedInstances)
            || array_key_exists($id, $this->factories);
    }

    public function has(string $id): bool
    {
        if ($this->hasBinding($id)) {
            return true;
        }
        if (isset($this->instantiableCache[$id])) {
            return $this->instantiableCache[$id];
        }

        return $this->instantiableCache[$id] = class_exists($id) && (new ReflectionClass($id))->isInstantiable();
    }

    public function get(string $id): mixed
    {
        // Prevent persistent-runtime cross-request/cross-tenant state leaks: a singleton MUST NEVER capture a scoped service
        if ('scoped' === ($this->lifetimes[$id] ?? null)) {
            foreach (array_keys($this->resolving) as $ancestor) {
                if ('singleton' === ($this->lifetimes[$ancestor] ?? null)) {
                    throw new ContainerException(sprintf(
                        'Captive scoped dependency rejected: singleton "%s" cannot capture per-scope service "%s".',
                        $ancestor,
                        $id,
                    ));
                }
            }
        }

        if (array_key_exists($id, $this->singletons)) {
            return $this->singletons[$id];
        }
        if (array_key_exists($id, $this->scopedInstances)) {
            return $this->scopedInstances[$id];
        }

        if (isset($this->resolving[$id])) {
            $chain = implode(' -> ', [...array_keys($this->resolving), $id]);
            throw new ContainerException(sprintf('Circular dependency detected: %s.', $chain));
        }

        $this->resolving[$id] = true;

        try {
            if (isset($this->factories[$id])) {
                $value = ($this->factories[$id])($this);
                $lifetime = $this->lifetimes[$id] ?? 'transient';
                if ('singleton' === $lifetime) {
                    $this->singletons[$id] = $value;
                } elseif ('scoped' === $lifetime) {
                    $this->scopedInstances[$id] = $value;
                }

                return $value;
            }

            if (class_exists($id)) {
                return $this->autowire($id);
            }

            throw new NotFoundException(sprintf('Service "%s" is not bound and is not an instantiable class.', $id));
        } finally {
            unset($this->resolving[$id]);
        }
    }

    /**
     * Typed helper for resolving a class or interface with full static type inference.
     *
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    public function make(string $class): object
    {
        $resolved = $this->get($class);
        if (!$resolved instanceof $class) {
            throw new ContainerException(sprintf(
                'Service "%s" resolved to %s instead of %s.',
                $class,
                get_debug_type($resolved),
                $class,
            ));
        }

        return $resolved;
    }

    /** Clear all operation-scoped instances after a request/job finishes. */
    public function resetScope(): void
    {
        $this->scopedInstances = [];
    }

    /**
     * Return registered binding lifetimes for ApplicationGraph introspection.
     *
     * @return array<string, 'transient'|'singleton'|'scoped'>
     */
    public function registeredBindings(): array
    {
        $bindings = $this->lifetimes;
        ksort($bindings);

        return $bindings;
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    private function autowire(string $class): object
    {
        $plan = $this->autowirePlans[$class] ?? null;
        if (null === $plan) {
            $reflection = new ReflectionClass($class);
            if (!$reflection->isInstantiable()) {
                $this->instantiableCache[$class] = false;
                throw new ContainerException(sprintf('Class "%s" is not instantiable.', $class));
            }
            $this->instantiableCache[$class] = true;

            $plan = [];
            $constructor = $reflection->getConstructor();
            if (null !== $constructor) {
                foreach ($constructor->getParameters() as $parameter) {
                    $type = $parameter->getType();
                    $hasDefault = $parameter->isDefaultValueAvailable();
                    $plan[] = [
                        'name' => $parameter->getName(),
                        'classType' => ($type instanceof ReflectionNamedType && !$type->isBuiltin()) ? $type->getName() : null,
                        'hasDefault' => $hasDefault,
                        'default' => $hasDefault ? $parameter->getDefaultValue() : null,
                        'allowsNull' => $type instanceof ReflectionNamedType ? $type->allowsNull() : true,
                    ];
                }
            }
            $this->autowirePlans[$class] = $plan;
        }

        if ([] === $plan) {
            return new $class();
        }

        $arguments = [];
        foreach ($plan as $param) {
            if (null !== $param['classType']) {
                if ($this->has($param['classType'])) {
                    $arguments[] = $this->get($param['classType']);
                    continue;
                }
                if ($param['hasDefault']) {
                    $arguments[] = $param['default'];
                    continue;
                }
                if ($param['allowsNull']) {
                    $arguments[] = null;
                    continue;
                }

                throw new ContainerException(sprintf(
                    'Cannot resolve parameter "$%s" (%s) of %s::__construct().',
                    $param['name'],
                    $param['classType'],
                    $class,
                ));
            }

            if ($param['hasDefault']) {
                $arguments[] = $param['default'];
                continue;
            }

            throw new ContainerException(sprintf(
                'Cannot autowire scalar/untyped parameter "$%s" of %s::__construct(). Bind it explicitly.',
                $param['name'],
                $class,
            ));
        }

        return new $class(...$arguments);
    }
}
