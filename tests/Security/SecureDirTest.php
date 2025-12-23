<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Security;

use BlackCat\Config\Security\ConfigDirPolicy;
use BlackCat\Config\Security\SecurityException;
use BlackCat\Config\Security\SecureDir;
use PHPUnit\Framework\TestCase;

final class SecureDirTest extends TestCase
{
    public function testAcceptsStrictSecretsDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        try {
            SecureDir::assertSecureReadableDir($dir, ConfigDirPolicy::secretsDir());
            self::assertTrue(true);
        } finally {
            @rmdir($dir);
        }
    }

    public function testRejectsWorldReadableExecutableDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0755);
        try {
            $this->expectException(SecurityException::class);
            SecureDir::assertSecureReadableDir($dir, ConfigDirPolicy::secretsDir());
        } finally {
            @rmdir($dir);
        }
    }

    public function testRejectsGroupWritableDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0770);
        try {
            $this->expectException(SecurityException::class);
            SecureDir::assertSecureReadableDir($dir, ConfigDirPolicy::secretsDir());
        } finally {
            @rmdir($dir);
        }
    }

    public function testRejectsUnexpectedOwnerWhenRunningAsRoot(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            self::markTestSkipped('Root required to change directory ownership.');
        }
        if (!function_exists('chown')) {
            self::markTestSkipped('chown() is not available.');
        }

        $dir = $this->makeTmpDir(0700);

        if (!@chown($dir, 12345)) {
            @rmdir($dir);
            self::markTestSkipped('Unable to chown directory (permissions).');
        }

        try {
            $this->expectException(SecurityException::class);
            SecureDir::assertSecureReadableDir($dir, ConfigDirPolicy::secretsDir());
        } finally {
            @rmdir($dir);
        }
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-dir-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}
