<?php

declare(strict_types=1);

namespace BlackCat\Config\Security;

/**
 * Strict-by-default security policy for reading config from disk.
 *
 * This is a security layer: avoid adding env-based bypasses.
 */
final class ConfigFilePolicy
{
    public function __construct(
        public readonly bool $allowSymlinks = false,
        public readonly bool $allowWorldReadable = false,
        public readonly bool $allowGroupWritable = false,
        public readonly bool $allowWorldWritable = false,
        public readonly int $maxBytes = 1024 * 1024,
        public readonly bool $checkParentDirs = true,
        public readonly bool $enforceOwner = true,
    ) {
        if ($this->maxBytes < 1) {
            throw new \InvalidArgumentException('maxBytes must be >= 1');
        }
    }

    public static function strict(): self
    {
        return new self();
    }

    /**
     * Policy for non-secret JSON files (e.g. crypto manifest).
     *
     * Allows world-readable files, but still blocks writable perms and symlinks.
     */
    public static function publicReadable(): self
    {
        return new self(
            allowSymlinks: false,
            allowWorldReadable: true,
            allowGroupWritable: false,
            allowWorldWritable: false,
            maxBytes: 1024 * 1024,
            checkParentDirs: true,
            enforceOwner: false,
        );
    }
}
