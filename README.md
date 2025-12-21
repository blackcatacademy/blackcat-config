# BlackCat Config Hub

Konfigurační centrum pro celou `blackcatacademy`. Stage 1 jsme dokončili sjednocením loaderu, CLI a kontrolních nástrojů tak, aby každý profil (dev/staging/prod) měl:

- jednotný `profiles.php` s defaults (env proměnné, integrace na sousední repa, telemetry cíle),
- renderování `.env` šablon + export profile metadata,
- bezpečnostní checklist (TLS, povinné proměnné, secrets placeholders),
- integration checker (ověření, že CLI/binary závislosti existují),
- telemetry zapisovanou do `var/log/*.ndjson`,
- smoke test (`composer test`), který hlídá loader + checklisty.

## CLI

```
php bin/config profile:list
php bin/config profile:env dev
php bin/config profile:render-env staging build/staging.env
php bin/config integration:check prod
php bin/config security:check prod
php bin/config check                   # spustí celý Stage 1 checklist
```

První argument může být custom cesta k `profiles.php`, jinak se použije `config/profiles.php`. Každý příkaz zapše telemetry event (viz `var/log`).

## Telemetry

Kanál je konfigurovatelný v `config/profiles.php` (výchozí `file://.../var/log/config-*.ndjson`). `telemetry:tail <profile>` vypíše poslední záznamy.

## Tests

```
composer test
# nebo:
vendor/bin/phpunit
```

Testy validují profily přes security checklist a jednotkově ověřují chování integration checkeru.

## Runtime config (Stage 2 – security core)

Některé systémy blokují `getenv()` / ENV obecně. Pro runtime proto přidáváme **file-based config** s fail‑closed security kontrolami (bez env bypassů):

```php
use BlackCat\Config\Runtime\Config;

// Strict default policy: žádné symlinky, žádná world-readable/writable, žádná group-writable.
Config::initFromJsonFile('/etc/blackcat/config.json');

$dsn = Config::requireString('db.dsn'); // dot-notation
```

Bezpečnostní pravidla pro soubor (defaultně):
- config soubor nesmí být symlink
- config soubor nesmí být world-readable / group-writable / world-writable
- adresáře v cestě nesmí být group/world-writable (výjimka: sticky dirs typu `/tmp`), aby nešlo config podstrčit přes filesystem

Penetrační testy jsou v `tests/Security/SecureFileTest.php`.
