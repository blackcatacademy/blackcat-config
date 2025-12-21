<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Runtime\ConfigBootstrap;
use PHPUnit\Framework\TestCase;

final class ConfigBootstrapTest extends TestCase
{
    public function testTryLoadReturnsNullWhenNoFilesExist(): void
    {
        $repo = ConfigBootstrap::tryLoadFirstAvailableJsonFile([
            '/this/path/should/not/exist-' . bin2hex(random_bytes(4)) . '.json',
        ]);

        self::assertNull($repo);
    }

    public function testLoadReturnsRepoFromFirstExistingSecureFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.json';
        file_put_contents($path, "{\n  \"db\": {\"dsn\": \"mysql:host=localhost;dbname=test\"}\n}\n");
        chmod($path, 0600);

        try {
            $repo = ConfigBootstrap::loadFirstAvailableJsonFile([
                '/does/not/exist-' . bin2hex(random_bytes(4)) . '.json',
                $path,
            ]);

            self::assertSame('mysql:host=localhost;dbname=test', $repo->requireString('db.dsn'));
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-bootstrap-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}

