<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Runtime\RuntimeConfigInstaller;
use PHPUnit\Framework\TestCase;

final class RuntimeConfigInstallerTest extends TestCase
{
    public function testRecommendWritePathSkipsInsecureDirAndUsesNext(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $badDir = $base . '/bad';
        $goodDir = $base . '/good';

        mkdir($badDir, 0777, true);
        @chmod($badDir, 0777);

        mkdir($goodDir, 0700, true);
        @chmod($goodDir, 0700);

        $badPath = $badDir . '/config.runtime.json';
        $goodPath = $goodDir . '/config.runtime.json';

        try {
            $rec = RuntimeConfigInstaller::recommendWritePath([$badPath, $goodPath]);
            self::assertSame($goodPath, $rec['path']);
            self::assertArrayHasKey($badPath, $rec['rejected']);
        } finally {
            @unlink($badPath);
            @unlink($goodPath);
            @rmdir($badDir);
            @rmdir($goodDir);
            @rmdir($base);
        }
    }

    public function testIsLikelyWindowsMountPathDetectsWslDrives(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('WSL detection is POSIX-only.');
        }

        self::assertTrue(RuntimeConfigInstaller::isLikelyWindowsMountPath('/mnt/c/Users/jaine/.blackcat/config.runtime.json'));
        self::assertTrue(RuntimeConfigInstaller::isLikelyWindowsMountPath('/mnt/D/blackcat/config.runtime.json'));
        self::assertFalse(RuntimeConfigInstaller::isLikelyWindowsMountPath('/home/jaine/.config/blackcat/config.runtime.json'));
    }

    public function testInitSkipsInsecureCandidateAndUsesNext(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $badDir = $base . '/bad';
        $goodDir = $base . '/good';

        mkdir($badDir, 0777, true);
        @chmod($badDir, 0777);

        mkdir($goodDir, 0700, true);
        @chmod($goodDir, 0700);

        $badPath = $badDir . '/config.runtime.json';
        $goodPath = $goodDir . '/config.runtime.json';

        try {
            $res = RuntimeConfigInstaller::init(['hello' => 'world'], null, false, [$badPath, $goodPath]);
            self::assertSame($goodPath, $res['path']);
            self::assertTrue($res['created']);
            self::assertFileExists($goodPath);

            $mode = fileperms($goodPath);
            self::assertIsInt($mode);
            self::assertSame(0600, $mode & 0777);
        } finally {
            @unlink($badPath);
            @unlink($goodPath);
            @rmdir($badDir);
            @rmdir($goodDir);
            @rmdir($base);
        }
    }

    public function testInitIsIdempotentWhenFileAlreadySecure(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.runtime.json';

        try {
            $first = RuntimeConfigInstaller::init(['a' => 1], $path, false);
            self::assertSame($path, $first['path']);
            self::assertTrue($first['created']);

            $second = RuntimeConfigInstaller::init(['a' => 2], $path, false);
            self::assertSame($path, $second['path']);
            self::assertFalse($second['created']);

            $raw = file_get_contents($path);
            self::assertIsString($raw);
            self::assertStringContainsString('"a": 1', $raw);
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-installer-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}
