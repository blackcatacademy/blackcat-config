<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Security\SecurityException;
use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Config\Runtime\RuntimeConfigValidator;
use PHPUnit\Framework\TestCase;

final class RuntimeConfigValidatorTest extends TestCase
{
    public function testCryptoConfigRequiresKeysDir(): void
    {
        $repo = ConfigRepository::fromArray(['crypto' => []]);
        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertCryptoConfig($repo);
    }

    public function testCryptoConfigValidatesKeysDirAndManifest(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $keysDir = $this->makeTmpDir(0700);
        $manifest = $keysDir . '/manifest.json';
        file_put_contents($manifest, "{\n  \"slots\": {}\n}\n");
        @chmod($manifest, 0644); // public-readable allowed for manifest policy

        try {
            $repo = ConfigRepository::fromArray([
                'crypto' => [
                    'keys_dir' => $keysDir,
                    'manifest' => $manifest,
                ],
            ]);

            RuntimeConfigValidator::assertCryptoConfig($repo);
            self::assertTrue(true);
        } finally {
            @unlink($manifest);
            @rmdir($keysDir);
        }
    }

    public function testObservabilityConfigRequiresStorageDir(): void
    {
        $repo = ConfigRepository::fromArray(['observability' => []]);
        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertObservabilityConfig($repo);
    }

    public function testObservabilityConfigValidatesStorageDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $storageDir = $this->makeTmpDir(0700);
        try {
            $repo = ConfigRepository::fromArray([
                'observability' => [
                    'storage_dir' => $storageDir,
                    'service' => 'blackcat-app',
                ],
            ]);

            RuntimeConfigValidator::assertObservabilityConfig($repo);
            self::assertTrue(true);
        } finally {
            @rmdir($storageDir);
        }
    }

    public function testObservabilityConfigRejectsSymlinkStorageDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\' || !function_exists('symlink')) {
            self::markTestSkipped('Symlink test not supported on this platform.');
        }

        $base = $this->makeTmpDir(0700);
        $target = $base . '/target';
        $link = $base . '/storage';
        if (!mkdir($target, 0700, true) && !is_dir($target)) {
            self::fail('Cannot create target dir: ' . $target);
        }
        @chmod($target, 0700);

        try {
            if (!@symlink($target, $link)) {
                self::markTestSkipped('Unable to create symlink (permissions).');
            }

            $repo = ConfigRepository::fromArray([
                'observability' => [
                    'storage_dir' => $link,
                ],
            ]);

            $this->expectException(SecurityException::class);
            RuntimeConfigValidator::assertObservabilityConfig($repo);
        } finally {
            @unlink($link);
            @rmdir($target);
            @rmdir($base);
        }
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-keys-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}
