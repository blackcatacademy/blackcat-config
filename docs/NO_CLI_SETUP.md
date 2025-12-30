# No-CLI setup (library API)

Some platforms do not allow CLI execution (no `php` binary, blocked `exec()`, restricted filesystem access, etc.).
`blackcat-config` still provides a safe, **fail-closed** setup path via its PHP API.

This document shows how to do the same work as `blackcat config …` without relying on `blackcat-cli`.

## 1) Recommend the best runtime-config path

```php
use BlackCat\Config\Runtime\RuntimeConfigInstaller;

$recommendation = RuntimeConfigInstaller::recommendWritePath();
// ['path' => '/etc/blackcat/config.runtime.json', 'reason' => '...']
```

## 2) Initialize a runtime config file from a template

```php
use BlackCat\Config\Runtime\RuntimeConfigInstaller;
use BlackCat\Config\Runtime\Templates\TrustKernelEdgenTemplate;

$seed = TrustKernelEdgenTemplate::build('full'); // or: 'root_uri' for compatibility mode

$res = RuntimeConfigInstaller::init(
    $seed,
    '/etc/blackcat/config.runtime.json',
    true // force overwrite/replace if needed
);
// ['path' => '...', 'created' => bool, 'rejected' => [...]]
```

## 3) Load + validate before boot

```php
use BlackCat\Config\Runtime\Config;
use BlackCat\Config\Runtime\RuntimeConfigValidator;

Config::initFromJsonFile('/etc/blackcat/config.runtime.json');

// Fail-closed validation (throws on invalid config):
RuntimeConfigValidator::assertTrustKernelWeb3Config(Config::repo());
RuntimeConfigValidator::assertCryptoConfig(Config::repo());
```

## 4) Inspect security posture (“doctor”)

```php
use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Config\Runtime\RuntimeDoctor;

$repo = ConfigRepository::fromJsonFile('/etc/blackcat/config.runtime.json');
$report = RuntimeDoctor::inspect($repo);
// ['ok' => bool, 'findings' => [...], 'summary' => [...], ...]
```

## 5) Compute on-chain attestations (optional hardening)

```php
use BlackCat\Config\Security\KernelAttestations;

$runtimeConfig = Config::repo()->toArray();
$key = KernelAttestations::runtimeConfigAttestationKeyV1();
$value = KernelAttestations::runtimeConfigAttestationValueV1($runtimeConfig);
```

These key/value pairs are designed to be set+locked in `InstanceController.attestations`.

## Important note (security)

Writing `/etc/blackcat/*` from a web runtime is not recommended. Treat runtime config, keys, and DB credentials as **operator-owned** assets:
- create them during installation (root/privileged context),
- lock down permissions (no symlinks, no world-writable dirs),
- keep secrets out of the web runtime (use a local agent boundary where possible).

