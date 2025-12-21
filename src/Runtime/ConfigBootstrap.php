<?php

declare(strict_types=1);

namespace BlackCat\Config\Runtime;

use BlackCat\Config\Security\ConfigFilePolicy;

final class ConfigBootstrap
{
    /**
     * @return list<string>
     */
    public static function defaultJsonPaths(): array
    {
        return [
            '/etc/blackcat/config.json',
            '/etc/blackcat/config.runtime.json',
            '/etc/blackcat/blackcat.json',
            '/run/secrets/blackcat-config.json',
            '/run/secrets/blackcat.json',
        ];
    }

    /**
     * @param list<string>|null $paths Candidate absolute paths to try.
     */
    public static function tryLoadFirstAvailableJsonFile(?array $paths = null, ?ConfigFilePolicy $policy = null): ?ConfigRepository
    {
        $paths ??= self::defaultJsonPaths();

        foreach ($paths as $path) {
            $path = trim((string)$path);
            if ($path === '') {
                continue;
            }
            if (!is_file($path)) {
                continue;
            }
            return ConfigRepository::fromJsonFile($path, $policy);
        }

        return null;
    }

    /**
     * @param list<string>|null $paths Candidate absolute paths to try.
     */
    public static function loadFirstAvailableJsonFile(?array $paths = null, ?ConfigFilePolicy $policy = null): ConfigRepository
    {
        $repo = self::tryLoadFirstAvailableJsonFile($paths, $policy);
        if ($repo !== null) {
            return $repo;
        }

        $paths ??= self::defaultJsonPaths();
        throw new \RuntimeException(sprintf(
            'No runtime config file found (tried: %s).',
            implode(', ', array_map(static fn(string $p): string => '"' . $p . '"', $paths)),
        ));
    }
}

