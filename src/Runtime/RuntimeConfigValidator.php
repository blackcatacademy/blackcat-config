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
        $keysDir = $repo->requireString('crypto.keys_dir');
        SecureDir::assertSecureReadableDir($keysDir, ConfigDirPolicy::secretsDir());

        $manifest = $repo->get('crypto.manifest');
        if ($manifest === null || $manifest === '') {
            return;
        }
        if (!is_string($manifest)) {
            throw new \RuntimeException('Invalid config type for crypto.manifest (expected string).');
        }

        SecureFile::assertSecureReadableFile($manifest, ConfigFilePolicy::publicReadable());
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
        $storageDir = $repo->requireString('observability.storage_dir');
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
}
