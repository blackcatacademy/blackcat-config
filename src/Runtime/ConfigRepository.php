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
    private function __construct(
        private readonly array $data,
        private readonly ?string $sourcePath,
    )
    {
    }

    /**
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data, null);
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
        return new self($decoded, $path);
    }

    public function sourcePath(): ?string
    {
        return $this->sourcePath;
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

    public function requireInt(string $key): int
    {
        $val = $this->get($key);
        if (is_int($val)) {
            return $val;
        }
        if (is_string($val)) {
            $trimmed = trim($val);
            if ($trimmed !== '' && ctype_digit($trimmed)) {
                return (int) $trimmed;
            }
        }

        throw new \RuntimeException('Missing required config integer: ' . $key);
    }

    /**
     * Resolve a potentially relative filesystem path value against the config source directory.
     *
     * Relative paths are resolved relative to the config JSON file location, not the process CWD.
     */
    public function resolvePath(string $path): string
    {
        $path = trim($path);
        if ($path === '') {
            throw new \RuntimeException('Config path is empty.');
        }
        if (str_contains($path, "\0")) {
            throw new \RuntimeException('Config path contains null byte.');
        }

        if (self::isAbsolutePath($path)) {
            return $path;
        }

        if ($this->sourcePath === null) {
            throw new \RuntimeException('Relative paths require a config sourcePath (load via fromJsonFile).');
        }

        $baseDir = dirname($this->sourcePath);
        if ($baseDir === '' || $baseDir === '.') {
            throw new \RuntimeException('Unable to resolve relative path (invalid config sourcePath): ' . $this->sourcePath);
        }

        return rtrim($baseDir, "/\\") . DIRECTORY_SEPARATOR . $path;
    }

    private static function isAbsolutePath(string $path): bool
    {
        if ($path === '') {
            return false;
        }

        if ($path[0] === '/' || $path[0] === '\\') {
            return true;
        }

        return (bool) preg_match('~^[a-zA-Z]:[\\\\/]~', $path);
    }

    /**
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return $this->data;
    }
}
