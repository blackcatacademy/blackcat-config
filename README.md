# BlackCat Config

Central configuration and hardening layer for the `blackcatacademy` ecosystem.

This repo is intentionally **security-first**:
- **Fail-closed** defaults (no “env bypass” switches for security-critical paths).
- **File-based runtime config** for environments where `getenv()`/ENV is blocked.
- Permission checks to prevent config/keys path tampering.

## Stage 1: Profiles + CLI

Stage 1 focuses on “profiles” (dev/staging/prod) and operational checks:
- unified `profiles.php` with defaults (env vars, integrations, telemetry sinks),
- `.env` template rendering + profile metadata export,
- security checklist (TLS, required vars, secret placeholders),
- integration checker (required binaries/CLIs),
- telemetry to `var/log/*.ndjson`,
- smoke test (`composer test`) to keep the pipeline stable.

### CLI

```bash
php bin/config profile:list
php bin/config profile:env dev
php bin/config profile:render-env staging build/staging.env
php bin/config integration:check prod
php bin/config security:check prod
php bin/config check
```

The first argument can be a custom `profiles.php` path; otherwise `config/profiles.php` is used.

## Stage 2: Runtime config (security core)

Some runtimes block `getenv()`/ENV entirely. Stage 2 provides **file-based runtime config** with strict permission checks:

```php
use BlackCat\Config\Runtime\Config;

Config::initFromJsonFile('/etc/blackcat/config.runtime.json');

$dsn = Config::requireString('db.dsn'); // dot-notation
```

Path resolution:
- filesystem paths inside the runtime config (e.g. `crypto.keys_dir`, `crypto.manifest`) can be relative,
  but they are resolved **relative to the config file location**, not the process working directory.

Default security rules (POSIX):
- config file must not be a symlink
- config file must not be world-readable / group-writable / world-writable
- config file must be owned by root or the current user (when ownership is available)
- parent directories must not be group/world-writable (sticky dirs like `/tmp` are allowed)

WSL note:
- avoid storing security-critical config on Windows mounts like `/mnt/c` (DrvFS); prefer the WSL filesystem (e.g. `~/.config/blackcat` or `/etc/blackcat`).

Penetration-style tests live in `tests/Security/SecureFileTest.php`.

## Trust model & integrity

Encryption requires a clear trust model (provenance + tamper detection). Design notes:
- `blackcat-config/docs/TRUST_MODEL.md`

## Stage 3: Config discovery helpers

If you need deterministic discovery (without env), use:

```php
use BlackCat\Config\Runtime\Config;

Config::initFromFirstAvailableJsonFileIfNeeded(); // default locations
```

Default candidates are defined in `blackcat-config/src/Runtime/ConfigBootstrap.php` and are platform-specific.

Defaults (summary):
- POSIX: `/etc/blackcat/*.json`, `/run/secrets/*.json`, plus user paths like `~/.config/blackcat/*.json`.
- Windows: `C:\ProgramData\BlackCat\*.json` and `%APPDATA%\BlackCat\*.json` when available.

Discovery behavior:
- if a candidate file exists but is rejected (permissions/symlink/invalid JSON), discovery continues to the next one
- `loadFirstAvailableJsonFile()` reports rejected files in the exception message (diagnostics)

To create a runtime config file in the best available location (auto-recommended), use:

```bash
php bin/config runtime:recommend
php bin/config runtime:init
```

`runtime:init` creates (or reuses) the first path that can be made valid under strict rules.

## Stage 4+: Runtime crypto config validation

Security-critical crypto settings can be validated before boot:

```php
use BlackCat\Config\Runtime\Config;
use BlackCat\Config\Runtime\RuntimeConfigValidator;

RuntimeConfigValidator::assertCryptoConfig(Config::repo());
```

Validation includes:
- `crypto.keys_dir` is required and must be a secure directory (`SecureDir`)
- `crypto.manifest` is optional; public-readable is allowed, but it must not be writable/symlink

Relevant tests:
- `blackcat-config/tests/Security/SecureDirTest.php`
- `blackcat-config/tests/Runtime/RuntimeConfigValidatorTest.php`

## Stage 5: Trust kernel config (Web3 / EVM)

Runtime config keys (recommended baseline):

```json
{
  "trust": {
    "integrity": {
      "root_dir": "/srv/blackcat",
      "manifest": "/etc/blackcat/integrity.manifest.json"
    },
    "web3": {
      "chain_id": 4207,
      "rpc_endpoints": ["https://rpc.layeredge.io"],
      "rpc_quorum": 1,
      "max_stale_sec": 180,
      "timeout_sec": 5,
      "mode": "full",
      "contracts": {
        "instance_controller": "0x1111111111111111111111111111111111111111",
        "release_registry": "0x2222222222222222222222222222222222222222"
      },
      "tx_outbox_dir": "/var/lib/blackcat/tx-outbox"
    }
  }
}
```

Enforcement note:
- Production vs dev behavior must **not** be switchable by editing runtime config.
- In the BlackCat design, enforcement is bound to the **on-chain policy hash** committed in `InstanceController.activePolicyHash`.
  The runtime config may still contain `trust.enforcement` for backwards compatibility, but the trust-kernel runtime in `blackcat-core` does not use it.

Defaults and rules:
- `max_stale_sec` recommended production default is `180` (fail-closed after stale).
- RPC endpoints must be `https://` (plain HTTP is allowed only for localhost).
- `rpc_quorum` must be in `1..count(rpc_endpoints)`.
- `trust.integrity.root_dir` must be an absolute, readable directory and must not be writable by group/world.
- `trust.integrity.manifest` must be an absolute, readable file and must not be writable or a symlink.

Validate Web3 trust-kernel config:

```php
use BlackCat\Config\Runtime\Config;
use BlackCat\Config\Runtime\RuntimeConfigValidator;

Config::initFromFirstAvailableJsonFile();
RuntimeConfigValidator::assertTrustKernelWeb3Config(Config::repo());
```

Edgen Chain template:
- `blackcat-config/docs/TRUST_KERNEL_EDGEN.md`
- CLI helpers:
  - `php bin/config runtime:template:trust-edgen` (recommended strict default; `mode="full"`)
  - `php bin/config runtime:template:trust-edgen-compat` (compat; `mode="root_uri"`, weaker)
  - `php bin/config runtime:init --template=trust-edgen` (writes a strict config to the best available location)

## Stage 6: Source code policy scan (anti-bypass)

To keep the kernel security model intact, you can scan your repo for known bypass patterns:

```bash
php bin/config security:scan .
php bin/config security:attack-surface .
```
