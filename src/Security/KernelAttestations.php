<?php

declare(strict_types=1);

namespace BlackCat\Config\Security;

final class KernelAttestations
{
    private const RUNTIME_CONFIG_ATTESTATION_KEY_LABEL_V1 = 'blackcat.runtime_config.canonical_sha256.v1';

    public static function runtimeConfigAttestationKeyV1(): string
    {
        return '0x' . hash('sha256', self::RUNTIME_CONFIG_ATTESTATION_KEY_LABEL_V1);
    }

    /**
     * @param array<string,mixed> $runtimeConfig
     */
    public static function runtimeConfigAttestationValueV1(array $runtimeConfig): string
    {
        return CanonicalJson::sha256Bytes32($runtimeConfig);
    }
}

