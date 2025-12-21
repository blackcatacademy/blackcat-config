<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

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

