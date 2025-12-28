<?php

declare(strict_types=1);

namespace BlackCat\Config\Security;

final class KernelAttestations
{
    private const RUNTIME_CONFIG_ATTESTATION_KEY_LABEL_V1 = 'blackcat.runtime_config.canonical_sha256.v1';
    private const COMPOSER_LOCK_ATTESTATION_KEY_LABEL_V1 = 'blackcat.composer.lock.canonical_sha256.v1';
    private const PHP_FINGERPRINT_ATTESTATION_KEY_LABEL_V1 = 'blackcat.php.fingerprint.canonical_sha256.v1';
    private const IMAGE_DIGEST_ATTESTATION_KEY_LABEL_V1 = 'blackcat.image.digest.sha256.v1';

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

    public static function composerLockAttestationKeyV1(): string
    {
        return '0x' . hash('sha256', self::COMPOSER_LOCK_ATTESTATION_KEY_LABEL_V1);
    }

    /**
     * @param array<string,mixed> $composerLock
     */
    public static function composerLockAttestationValueV1(array $composerLock): string
    {
        return CanonicalJson::sha256Bytes32($composerLock);
    }

    public static function phpFingerprintAttestationKeyV1(): string
    {
        return '0x' . hash('sha256', self::PHP_FINGERPRINT_ATTESTATION_KEY_LABEL_V1);
    }

    /**
     * @return array{schema_version:int,type:string,php_version:string,php_sapi:string,extensions:array<string,string|null>}
     */
    public static function phpFingerprintPayloadV1(): array
    {
        $extensions = get_loaded_extensions();
        sort($extensions, SORT_STRING);

        $map = [];
        foreach ($extensions as $ext) {
            if (!is_string($ext) || $ext === '') {
                continue;
            }
            $version = phpversion($ext);
            $map[$ext] = is_string($version) && trim($version) !== '' ? trim($version) : null;
        }

        return [
            'schema_version' => 1,
            'type' => 'blackcat.php.fingerprint',
            'php_version' => PHP_VERSION,
            'php_sapi' => PHP_SAPI,
            'extensions' => $map,
        ];
    }

    /**
     * @param array{schema_version:int,type:string,php_version:string,php_sapi:string,extensions:array<string,string|null>} $payload
     */
    public static function phpFingerprintAttestationValueV1(array $payload): string
    {
        return CanonicalJson::sha256Bytes32($payload);
    }

    public static function imageDigestAttestationKeyV1(): string
    {
        return '0x' . hash('sha256', self::IMAGE_DIGEST_ATTESTATION_KEY_LABEL_V1);
    }

    /**
     * Canonical value is the raw 32-byte sha256 digest (as bytes32 hex).
     *
     * Accepts:
     * - "sha256:<64-hex>"
     * - "0x<64-hex>"
     * - "<64-hex>"
     */
    public static function imageDigestAttestationValueV1(string $digest): string
    {
        $digest = trim($digest);
        if ($digest === '' || str_contains($digest, "\0")) {
            throw new \InvalidArgumentException('Invalid image digest string.');
        }

        if (str_starts_with($digest, 'sha256:')) {
            $digest = substr($digest, 7);
        }

        if (str_starts_with($digest, '0x') || str_starts_with($digest, '0X')) {
            $digest = substr($digest, 2);
        }

        $digest = trim($digest);
        if (!preg_match('/^[a-fA-F0-9]{64}$/', $digest)) {
            throw new \InvalidArgumentException('Image digest must be 32 bytes of hex (sha256).');
        }

        return '0x' . strtolower($digest);
    }
}
