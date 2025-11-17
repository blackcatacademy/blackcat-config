<?php

declare(strict_types=1);

namespace BlackCat\Config;

/**
 * Auto-generated descriptor stub to anchor blackcat-config source tree.
 * Populate orchestrators/services per docs/ROADMAP.md.
 */
final class Manifest
{
    public const REPOSITORY = 'blackcat-config';

    public static function describe(): array
    {
        return [
            'repository' => self::REPOSITORY,
            'role' => 'Config hub.',
            'integrations' => 'Profiles, env templates, secrets overlays powering installer/deployer.',
            'status' => 'bootstrap',
        ];
    }
}
