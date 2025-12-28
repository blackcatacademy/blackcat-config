<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Config\Runtime\RuntimeDoctor;
use PHPUnit\Framework\TestCase;

final class RuntimeDoctorTest extends TestCase
{
    public function testDoctorWarnsWhenTrustKernelIsNotConfigured(): void
    {
        $repo = ConfigRepository::fromArray([]);

        $res = RuntimeDoctor::inspect($repo);

        self::assertTrue($res['ok']);
        self::assertSame('compat', $res['tier']);
        self::assertTrue($this->hasFindingCode($res['findings'], 'trust_kernel_not_configured'));
    }

    public function testDoctorReportsRecommendedTrustKernelHardening(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX filesystem required.');
        }

        $rootDir = $this->makeTmpDir(0755);
        $manifestPath = $rootDir . '/integrity.manifest.json';
        file_put_contents($manifestPath, "{\n  \"schema_version\": 1,\n  \"type\": \"blackcat.integrity.manifest\",\n  \"files\": {\"a.txt\": \"0x" . str_repeat("00", 32) . "\"}\n}\n");
        @chmod($manifestPath, 0644);

        try {
            $repo = ConfigRepository::fromArray([
                'trust' => [
                    'integrity' => [
                        'root_dir' => $rootDir,
                        'manifest' => $manifestPath,
                    ],
                    'web3' => [
                        'chain_id' => 4207,
                        'rpc_endpoints' => ['https://rpc.layeredge.io'],
                        'rpc_quorum' => 1,
                        'mode' => 'full',
                        'contracts' => [
                            'instance_controller' => '0x1111111111111111111111111111111111111111',
                        ],
                    ],
                ],
            ]);

            $res = RuntimeDoctor::inspect($repo);

            self::assertTrue($res['ok'], 'doctor should not report hard errors for recommended posture warnings');
            self::assertSame('medium', $res['tier']);
            self::assertTrue($this->hasFindingCode($res['findings'], 'rpc_quorum_insecure_for_strict'));
            self::assertTrue($this->hasFindingCode($res['findings'], 'crypto_agent_missing'));
            self::assertTrue($this->hasFindingCode($res['findings'], 'tx_outbox_not_configured'));
        } finally {
            @unlink($manifestPath);
            @rmdir($rootDir);
        }
    }

    /**
     * @param list<array{code:string}> $findings
     */
    private function hasFindingCode(array $findings, string $code): bool
    {
        foreach ($findings as $f) {
            if ($f['code'] === $code) {
                return true;
            }
        }
        return false;
    }

    private function makeTmpDir(int $mode): string
    {
        $base = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $base . '/blackcat-config-doctor-' . bin2hex(random_bytes(6));
        mkdir($dir, $mode, true);
        @chmod($dir, $mode);
        return $dir;
    }
}
