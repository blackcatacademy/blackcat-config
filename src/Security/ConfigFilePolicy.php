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
    ) {
        if ($this->maxBytes < 1) {
            throw new \InvalidArgumentException('maxBytes must be >= 1');
        }
    }

    public static function strict(): self
    {
        return new self();
    }
}

