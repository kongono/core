<?php

declare(strict_types=1);

namespace Kongono\Core\Diagnostics;

/**
 * Pluggable storage contract for Kongono's Production Incident Time-Machine.
 */
interface IncidentStoreInterface
{
    public function record(IncidentRecord $incident): void;

    public function find(string $reference): ?IncidentRecord;

    /** @return list<IncidentRecord> */
    public function recent(int $limit = 20): array;
}
