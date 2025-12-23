<?php

declare(strict_types=1);

namespace BlackCat\Config\Runtime;

use BlackCat\Config\Security\ConfigDirPolicy;
use BlackCat\Config\Security\ConfigFilePolicy;
use BlackCat\Config\Security\SecureDir;
use BlackCat\Config\Security\SecureFile;

final class RuntimeConfigValidator
{
    /**
     * Validate security-critical crypto config.
     *
     * Required:
     * - crypto.keys_dir (secure directory)
     *
     * Optional:
     * - crypto.manifest (public-readable file is allowed, but must not be writable/symlink)
     */
    public static function assertCryptoConfig(ConfigRepository $repo): void
    {
        $keysDir = $repo->resolvePath($repo->requireString('crypto.keys_dir'));
        SecureDir::assertSecureReadableDir($keysDir, ConfigDirPolicy::secretsDir());

        $manifest = $repo->get('crypto.manifest');
        if ($manifest === null || $manifest === '') {
            return;
        }
        if (!is_string($manifest)) {
            throw new \RuntimeException('Invalid config type for crypto.manifest (expected string).');
        }

        SecureFile::assertSecureReadableFile($repo->resolvePath($manifest), ConfigFilePolicy::publicReadable());
    }

    /**
     * Validate observability local-store config.
     *
     * Required:
     * - observability.storage_dir (secure directory)
     *
     * Optional:
     * - observability.service (non-empty string)
     */
    public static function assertObservabilityConfig(ConfigRepository $repo): void
    {
        $storageDir = $repo->resolvePath($repo->requireString('observability.storage_dir'));
        SecureDir::assertSecureReadableDir($storageDir, ConfigDirPolicy::secretsDir());

        $service = $repo->get('observability.service');
        if ($service === null || $service === '') {
            return;
        }
        if (!is_string($service)) {
            throw new \RuntimeException('Invalid config type for observability.service (expected string).');
        }
        if (trim($service) === '') {
            throw new \RuntimeException('Invalid config value for observability.service (expected non-empty string).');
        }
    }

    /**
     * Validate Web3 trust-kernel configuration (EVM JSON-RPC).
     *
     * This config is optional until the trust-kernel runtime is fully adopted across the ecosystem.
     * If `trust.web3` is missing, this validator is a no-op.
     *
     * Required (when trust.web3 exists):
     * - trust.web3.chain_id (int)
     * - trust.web3.rpc_endpoints (non-empty list of HTTPS endpoints; HTTP allowed only for localhost)
     * - trust.web3.rpc_quorum (int; 1..count(rpc_endpoints))
     * - trust.web3.contracts.instance_controller (EVM address)
     *
     * Optional:
     * - trust.web3.contracts.release_registry (EVM address)
     * - trust.web3.max_stale_sec (int; default 180)
     * - trust.web3.mode ("root_uri" | "full"; default "root_uri")
     * - trust.web3.tx_outbox_dir (secure readable dir; recommended when buffering transactions)
     */
    public static function assertTrustKernelWeb3Config(ConfigRepository $repo): void
    {
        $web3 = $repo->get('trust.web3');
        if ($web3 === null) {
            return;
        }
        if (!is_array($web3)) {
            throw new \RuntimeException('Invalid config type for trust.web3 (expected object).');
        }

        $chainId = $repo->requireInt('trust.web3.chain_id');
        if ($chainId <= 0) {
            throw new \RuntimeException('Invalid config value for trust.web3.chain_id (expected > 0).');
        }

        $endpoints = $repo->get('trust.web3.rpc_endpoints');
        if (!is_array($endpoints) || $endpoints === []) {
            throw new \RuntimeException('Missing required config list: trust.web3.rpc_endpoints');
        }

        $normalizedEndpoints = [];
        foreach ($endpoints as $i => $endpoint) {
            if (!is_string($endpoint)) {
                throw new \RuntimeException('Invalid config type for trust.web3.rpc_endpoints[' . $i . '] (expected string).');
            }
            $endpoint = trim($endpoint);
            if ($endpoint === '') {
                throw new \RuntimeException('Invalid config value for trust.web3.rpc_endpoints[' . $i . '] (expected non-empty string).');
            }
            if (str_contains($endpoint, "\0")) {
                throw new \RuntimeException('Invalid config value for trust.web3.rpc_endpoints[' . $i . '] (contains null byte).');
            }
            if (!self::isAllowedRpcEndpoint($endpoint)) {
                throw new \RuntimeException(
                    'Invalid config value for trust.web3.rpc_endpoints[' . $i . ']: endpoint must be https:// (http:// allowed only for localhost).'
                );
            }

            $normalizedEndpoints[] = $endpoint;
        }

        $quorumRaw = $repo->get('trust.web3.rpc_quorum', 1);
        $quorum = self::parseIntLike($quorumRaw, 'trust.web3.rpc_quorum');
        $max = count($normalizedEndpoints);
        if ($quorum < 1 || $quorum > $max) {
            throw new \RuntimeException('Invalid config value for trust.web3.rpc_quorum (expected 1..' . $max . ').');
        }

        $maxStaleRaw = $repo->get('trust.web3.max_stale_sec', 180);
        $maxStaleSec = self::parseIntLike($maxStaleRaw, 'trust.web3.max_stale_sec');
        if ($maxStaleSec < 1 || $maxStaleSec > 86400) {
            throw new \RuntimeException('Invalid config value for trust.web3.max_stale_sec (expected 1..86400).');
        }

        $modeRaw = $repo->get('trust.web3.mode', 'root_uri');
        if (!is_string($modeRaw)) {
            throw new \RuntimeException('Invalid config type for trust.web3.mode (expected string).');
        }
        $mode = strtolower(trim($modeRaw));
        if ($mode === '' || !in_array($mode, ['root_uri', 'full'], true)) {
            throw new \RuntimeException('Invalid config value for trust.web3.mode (expected "root_uri" or "full").');
        }

        $controller = $repo->requireString('trust.web3.contracts.instance_controller');
        self::assertEvmAddress($controller, 'trust.web3.contracts.instance_controller');

        $releaseRegistry = $repo->get('trust.web3.contracts.release_registry');
        if ($releaseRegistry !== null && $releaseRegistry !== '') {
            if (!is_string($releaseRegistry)) {
                throw new \RuntimeException('Invalid config type for trust.web3.contracts.release_registry (expected string).');
            }
            self::assertEvmAddress($releaseRegistry, 'trust.web3.contracts.release_registry');
        }

        $factory = $repo->get('trust.web3.contracts.instance_factory');
        if ($factory !== null && $factory !== '') {
            if (!is_string($factory)) {
                throw new \RuntimeException('Invalid config type for trust.web3.contracts.instance_factory (expected string).');
            }
            self::assertEvmAddress($factory, 'trust.web3.contracts.instance_factory');
        }

        $txOutboxDir = $repo->get('trust.web3.tx_outbox_dir');
        if ($txOutboxDir !== null && $txOutboxDir !== '') {
            if (!is_string($txOutboxDir)) {
                throw new \RuntimeException('Invalid config type for trust.web3.tx_outbox_dir (expected string).');
            }
            $resolvedOutboxDir = $repo->resolvePath($txOutboxDir);
            SecureDir::assertSecureReadableDir($resolvedOutboxDir, ConfigDirPolicy::secretsDir());
            if (!is_writable($resolvedOutboxDir)) {
                throw new \RuntimeException('Config directory is not writable: trust.web3.tx_outbox_dir');
            }
        }
    }

    private static function parseIntLike(mixed $value, string $key): int
    {
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value)) {
            $trimmed = trim($value);
            if ($trimmed !== '' && ctype_digit($trimmed)) {
                return (int) $trimmed;
            }
        }

        throw new \RuntimeException('Invalid config type/value for ' . $key . ' (expected integer).');
    }

    private static function isAllowedRpcEndpoint(string $endpoint): bool
    {
        $endpoint = trim($endpoint);
        if ($endpoint === '') {
            return false;
        }

        $parts = @parse_url($endpoint);
        if (!is_array($parts)) {
            return false;
        }

        $scheme = $parts['scheme'] ?? null;
        if (!is_string($scheme) || $scheme === '') {
            return false;
        }
        $scheme = strtolower($scheme);

        if ($scheme === 'https') {
            return true;
        }

        if ($scheme !== 'http') {
            return false;
        }

        $host = $parts['host'] ?? null;
        if (!is_string($host) || $host === '') {
            return false;
        }
        $host = strtolower($host);

        return $host === 'localhost' || $host === '127.0.0.1' || $host === '::1';
    }

    private static function assertEvmAddress(string $address, string $key): void
    {
        $address = trim($address);
        if ($address === '') {
            throw new \RuntimeException('Missing required config string: ' . $key);
        }

        if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $address)) {
            throw new \RuntimeException('Invalid EVM address for ' . $key . '.');
        }

        if (strtolower($address) === '0x0000000000000000000000000000000000000000') {
            throw new \RuntimeException('Invalid EVM address for ' . $key . ' (zero address).');
        }
    }
}
