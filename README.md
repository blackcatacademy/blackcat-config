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

Config::initFromJsonFile('/etc/blackcat/config.json');

$dsn = Config::requireString('db.dsn'); // dot-notation
```

Default security rules (POSIX):
- config file must not be a symlink
- config file must not be world-readable / group-writable / world-writable
- parent directories must not be group/world-writable (sticky dirs like `/tmp` are allowed)

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
