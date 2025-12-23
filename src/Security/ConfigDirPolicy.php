<?php

declare(strict_types=1);

namespace BlackCat\Config\Security;

/**
 * Security policy for directories referenced from runtime config.
 */
final class ConfigDirPolicy
{
    public function __construct(
        public readonly bool $allowSymlinks = false,
        public readonly bool $allowGroupWritable = false,
        public readonly bool $allowWorldWritable = false,
        public readonly bool $allowWorldReadable = false,
        public readonly bool $allowWorldExecutable = false,
        public readonly bool $checkParentDirs = true,
        public readonly bool $enforceOwner = true,
    ) {
    }

    public static function strict(): self
    {
        return new self();
    }

    /**
     * Recommended defaults for secrets directories (keys, vaults, etc.).
     *
     * Allows group read/execute, but blocks any world access and all write perms
     * outside of the owner.
     */
    public static function secretsDir(): self
    {
        return new self(
            allowSymlinks: false,
            allowGroupWritable: false,
            allowWorldWritable: false,
            allowWorldReadable: false,
            allowWorldExecutable: false,
            checkParentDirs: true,
            enforceOwner: true,
        );
    }

    /**
     * Policy for a code/integrity root directory (not secret, but must not be writable).
     *
     * Allows world-read + world-exec (typical for deployed code trees), but blocks all group/world write access
     * and disallows symlinks to reduce the risk of path redirection.
     */
    public static function integrityRootDir(): self
    {
        return new self(
            allowSymlinks: false,
            allowGroupWritable: false,
            allowWorldWritable: false,
            allowWorldReadable: true,
            allowWorldExecutable: true,
            checkParentDirs: true,
            enforceOwner: false,
        );
    }
}
