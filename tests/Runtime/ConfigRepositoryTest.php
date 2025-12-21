<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Runtime\ConfigRepository;
use PHPUnit\Framework\TestCase;

final class ConfigRepositoryTest extends TestCase
{
    public function testDotNotationLookup(): void
    {
        $repo = ConfigRepository::fromArray([
            'db' => [
                'dsn' => 'mysql:host=localhost',
            ],
            'feature' => [
                'flags' => [
                    'a' => true,
                ],
            ],
        ]);

        self::assertSame('mysql:host=localhost', $repo->get('db.dsn'));
        self::assertSame(true, $repo->get('feature.flags.a'));
        self::assertSame(null, $repo->get('missing.key'));
        self::assertSame('x', $repo->get('missing.key', 'x'));
    }

    public function testRequireStringThrowsWhenMissing(): void
    {
        $repo = ConfigRepository::fromArray(['db' => []]);
        $this->expectException(\RuntimeException::class);
        $repo->requireString('db.dsn');
    }
}

