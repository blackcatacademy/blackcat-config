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

    public function testCryptoConfigResolvesPathsRelativeToConfigFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $keysDir = $base . '/keys';
        if (!mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
            self::fail('Cannot create keys dir: ' . $keysDir);
        }
        @chmod($keysDir, 0700);

        $manifestAbs = $keysDir . '/manifest.json';
        file_put_contents($manifestAbs, "{\n  \"slots\": {}\n}\n");
        @chmod($manifestAbs, 0644);

        $configPath = $base . '/config.runtime.json';
        $configJson = json_encode([
            'crypto' => [
                'keys_dir' => 'keys',
                'manifest' => 'keys/manifest.json',
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($configJson)) {
            self::fail('Unable to encode JSON.');
        }
        file_put_contents($configPath, $configJson . "\n");
        @chmod($configPath, 0600);

        try {
            $repo = ConfigRepository::fromJsonFile($configPath);
            RuntimeConfigValidator::assertCryptoConfig($repo);
            self::assertTrue(true);
        } finally {
            @unlink($configPath);
            @unlink($manifestAbs);
            @rmdir($keysDir);
            @rmdir($base);
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

    public function testTrustKernelValidatorIsNoOpWhenNotConfigured(): void
    {
        $repo = ConfigRepository::fromArray(['crypto' => ['keys_dir' => '/tmp']]);
        RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
        self::assertTrue(true);
    }

    public function testTrustKernelConfigRequiresChainIdWhenTrustPresent(): void
    {
        $repo = ConfigRepository::fromArray(['trust' => ['web3' => []]]);
        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
    }

    public function testTrustKernelConfigValidatesBasicFields(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $outboxDir = $this->makeTmpDir(0700);
        try {
            $repo = ConfigRepository::fromArray([
                'trust' => [
                    'web3' => [
                        'chain_id' => 4207,
                        'rpc_endpoints' => [
                            'https://rpc.layeredge.io',
                        ],
                        'rpc_quorum' => 1,
                        'max_stale_sec' => 180,
                        'mode' => 'root_uri',
                        'contracts' => [
                            'instance_controller' => '0x1111111111111111111111111111111111111111',
                            'release_registry' => '0x2222222222222222222222222222222222222222',
                            'instance_factory' => '0x3333333333333333333333333333333333333333',
                        ],
                        'tx_outbox_dir' => $outboxDir,
                    ],
                ],
            ]);

            RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
            self::assertTrue(true);
        } finally {
            @rmdir($outboxDir);
        }
    }

    public function testTrustKernelConfigRejectsNonTlsRpcEndpoint(): void
    {
        $repo = ConfigRepository::fromArray([
            'trust' => [
                'web3' => [
                    'chain_id' => 4207,
                    'rpc_endpoints' => ['http://rpc.layeredge.io'],
                    'rpc_quorum' => 1,
                    'contracts' => [
                        'instance_controller' => '0x1111111111111111111111111111111111111111',
                    ],
                ],
            ],
        ]);

        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
    }

    public function testTrustKernelConfigRejectsQuorumAboveEndpointsCount(): void
    {
        $repo = ConfigRepository::fromArray([
            'trust' => [
                'web3' => [
                    'chain_id' => 4207,
                    'rpc_endpoints' => [
                        'https://rpc.layeredge.io',
                        'https://rpc.layeredge.io',
                    ],
                    'rpc_quorum' => 3,
                    'contracts' => [
                        'instance_controller' => '0x1111111111111111111111111111111111111111',
                    ],
                ],
            ],
        ]);

        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
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
