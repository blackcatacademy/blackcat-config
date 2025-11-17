#!/usr/bin/env php
<?php

declare(strict_types=1);

require __DIR__ . '/../src/autoload.php';

use BlackCat\Config\Config\ProfileConfig;
use BlackCat\Config\Integration\IntegrationChecker;
use BlackCat\Config\Security\SecurityChecklist;

$config = ProfileConfig::fromFile(__DIR__ . '/../config/profiles.php');
$security = new SecurityChecklist();
$integrations = new IntegrationChecker();

$failures = [];

foreach ($config->profiles() as $profile) {
    $issues = array_merge(
        $security->validate($profile),
        $integrations->check($profile)
    );

    if ($issues !== []) {
        $failures[$profile->name()] = $issues;
    }
}

if ($failures !== []) {
    foreach ($failures as $name => $issues) {
        fwrite(STDERR, "[{$name}]" . PHP_EOL);
        foreach ($issues as $issue) {
            fwrite(STDERR, "  - {$issue}" . PHP_EOL);
        }
    }
    exit(1);
}

echo "ProfileConfig tests passed (" . count($config->profiles()) . " profiles)." . PHP_EOL;
