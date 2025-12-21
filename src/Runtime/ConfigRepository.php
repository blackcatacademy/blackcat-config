<?php

declare(strict_types=1);

namespace BlackCat\Config\Runtime;

use BlackCat\Config\Security\ConfigFilePolicy;
use BlackCat\Config\Security\SecureFile;

final class ConfigRepository
{
    /**
     * @param array<string,mixed> $data
     */
    private function __construct(private readonly array $data)
    {
    }

    /**
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data);
    }

    public static function fromJsonFile(string $path, ?ConfigFilePolicy $policy = null): self
    {
        SecureFile::assertSecureReadableFile($path, $policy);

        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new \RuntimeException('Unable to read config file: ' . $path);
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \RuntimeException('Invalid JSON config file: ' . $path, 0, $e);
        }

        if (!is_array($decoded)) {
            throw new \RuntimeException('Config JSON must decode to an object/array: ' . $path);
        }

        /** @var array<string,mixed> $decoded */
        return new self($decoded);
    }

    /**
     * Dot-notation lookup (e.g., "db.dsn").
     */
    public function get(string $key, mixed $default = null): mixed
    {
        if ($key === '') {
            return $default;
        }

        $cur = $this->data;
        foreach (explode('.', $key) as $segment) {
            if ($segment === '') {
                return $default;
            }
            if (!is_array($cur) || !array_key_exists($segment, $cur)) {
                return $default;
            }
            $cur = $cur[$segment];
        }

        return $cur;
    }

    public function requireString(string $key): string
    {
        $val = $this->get($key);
        if (!is_string($val) || $val === '') {
            throw new \RuntimeException('Missing required config string: ' . $key);
        }
        return $val;
    }

    /**
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return $this->data;
    }
}

