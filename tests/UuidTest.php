<?php

declare(strict_types=1);

namespace Kongono\Core\Tests;

use Kongono\Core\CoreException;
use Kongono\Core\Id\Uuid;
use PHPUnit\Framework\TestCase;

final class UuidTest extends TestCase
{
    public function testUuidV7IsValidTimeOrderedAndRoundTripsTimestamp(): void
    {
        $t1 = 1_764_180_000_000;
        $t2 = 1_764_180_005_123;

        $id1 = Uuid::v7($t1);
        $id2 = Uuid::v7($t2);

        self::assertTrue(Uuid::isValid($id1));
        self::assertTrue(Uuid::isValid($id2));
        self::assertSame(7, Uuid::version($id1));
        self::assertSame(7, Uuid::version($id2));
        self::assertSame($t1, Uuid::extractTimestampMs($id1));
        self::assertSame($t2, Uuid::extractTimestampMs($id2));
        self::assertLessThan(0, strcmp($id1, $id2));
        self::assertNotSame(Uuid::v7($t1), Uuid::v7($t1));
    }

    public function testUuidV4ValidationAndRejection(): void
    {
        $v4 = Uuid::v4();
        self::assertTrue(Uuid::isValid($v4));
        self::assertSame(4, Uuid::version($v4));
        self::assertNull(Uuid::extractTimestampMs($v4));

        self::assertFalse(Uuid::isValid('not-a-uuid'));
        self::assertFalse(Uuid::isValid('00000000-0000-0000-0000-000000000000'));
        self::assertNull(Uuid::version('not-a-uuid'));

        $this->expectException(CoreException::class);
        Uuid::v7(-1);
    }
}
