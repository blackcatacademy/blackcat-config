# Trust model & integrita (poznámky pro další vývoj)

Tento dokument je návrhová poznámka pro trust systém BlackCat. Klíčová myšlenka je:

> Šifrování je tak bezpečné, jak bezpečný je **trust model** okolo klíčů, konfigurace a původu kódu.

I “perfektní kryptografie” nepomůže, pokud jde systém potichu přenastavit (podvržené soubory, přesměrované moduly, změněný vygenerovaný kód).

## Cíle

- Defaultně být **tamper-evident** (a ve vyšších security tier i “tamper-resistant”).
- Mít jasný **řetězec důvěry** od “oficiální release” → “nainstalovaný systém” → “runtime”.
- Omezit reálné útoky (FTP chyba, kompromitovaný hosting, slabá práva, neúplné aktualizace).
- Udržet modularitu: čisté knihovny bez IO; CLI/monitoring/updater zvlášť repo.

## Bezpečnostní díry, které musíme zavřít

1) **Po instalaci se neověřuje původ/verze**
   - Útočník může nahradit soubory a systém je bude spouštět.
2) **Podvržení konfigurace / generovaných souborů**
   - V praxi se často dostane write přístup přes FTP, únik tokenu, nebo údržbu.
3) **Downgrade na HTTP během instalace**
   - Pokud bootstrap admina běží přes HTTP, jde odposlechnout heslo/session.

## Stavební bloky trust systému

### 1) Podepsané integrity manifesty (původ release)

Každý release publikuje:
- `integrity.json` (checksumy + metadata)
- `integrity.sig` (podpis)

`integrity.json` minimálně:
- jméno komponenty + verze (commit/tag)
- seznam souborů s `sha256` (nebo tree hash / Merkle root)
- metadata buildu (created_at, builder id, tooling verze)

Ověření musí stát na **pinned public keys** (root-of-trust). HTTPS na GitHub pomáhá, ale samo o sobě nestačí.

Kde hostovat:
- samostatný repo `blackcat-checksums` / `blackcat-trust-store`, nebo
- GitHub Release assets v každém repo.

### 2) Install snapshot (lokální původ)

Při instalaci vytvořit lokální snapshot:
- `installed.json` (co je nainstalované + hashe + odkazy na config)
- `installed.sig` (podpis)

To je baseline pro runtime kontroly a pro “kontrolu mimo systém”.

### 3) Podepisování generovaných souborů (lokální anti-tamper)

Každý soubor, který BlackCat vygeneruje (config overlay, šablony, schema output, …), podepsat:
- `file.ext` + `file.ext.sig`

Doporučení:
- **1 klíč = 1 účel** (config-signing, schema-signing, template-signing…)
- privátní klíče mimo webroot, striktní práva
- “extreme tier”: podpis přes HSM/KMS (lokální kompromitace pak nemůže podepsat nové soubory)

Bez HSM/KMS je to primárně **tamper-evident** (když útočník získá signing key na stejném hostu, může podepsat i podvrh). S HSM/KMS je to výrazně silnější.

### 4) Emergency reakce (“pause / safe mode”)

Když selže integrita kritických částí:
- fail-closed pro security core (nebootovat / zakázat writes / zakázat admin login)
- emitovat high-severity telemetry event
- volitelně vytvořit “maintenance lock” soubor, který zná installer/deployer

Chování může být tier-based, ale v produkci nesmí existovat tichý bypass.

## Out-of-band ověřování (“musí běžet mimo systém”)

Pro scénáře “hosting je kompromitovaný” musí ověřování běžet externě:
- CI/CD pipeline ověří deploy podle podepsaných manifestů před přepnutím trafficu.
- watchdog/agent (oddělený container/host) periodicky kontroluje drift a alertuje.

Tohle by mělo být standardní napojení pro `blackcat-monitoring` / `blackcat-observability`.

## Bezpečný bootstrap / installer (high-level)

- Bootstrap admina **vyžaduje HTTPS** (jinak se admin credentials nesmí vytvořit/akceptovat).
- Pokud se použije FTP/SFTP pro bootstrap:
  - jen na minimum času,
  - pak vypnout/omezit (policy + checklist + telemetry warning).
- Vygenerované admin heslo je dočasný token:
  - vynutit okamžitou změnu hesla,
  - ideálně out-of-band potvrzení session (email/magic link/WebAuthn).
- Pokud je přítomný `blackcat-jwt`, využít pro tvrdší session/bootstrap (krátké tokeny, audience binding, rotace).

## Návrh repozitářů (aby core zůstalo čisté)

**Knihovny (bez IO / bez network / bez CLI side-effect):**
- `blackcat-integrity` — hashing, verifikace podpisů, parsing manifestů, policy rozhodnutí.
- `blackcat-config` — runtime config + permission checks + validátory (tento repo).
- `blackcat-crypto` — crypto služby (už existuje).
- `blackcat-core` — minimální kernel (musí fungovat i samostatně).

**IO / nástroje pro platformu:**
- `blackcat-cli` — jednotný CLI entrypoint + commands (bez povinné závislosti v runtime bez CLI).
- `blackcat-installer` / `blackcat-install` — secure install + bootstrap enforcement.
- `blackcat-updater` — bezpečný update client (TUF-like, podepsaná metadata).
- `blackcat-sentinel` (nebo `blackcat-guard`) — out-of-band watchdog/agent.
- `blackcat-monitoring` / `blackcat-observability` — dashboardy, alerty, telemetry sinky.

## Doporučený rollout ve fázích

1) Definovat `integrity.json` schema + Ed25519 podpis; vyrobit v CI pro 1 repo.
2) Implementovat verifier v `blackcat-integrity` a expose v `blackcat-config` (API + CLI command).
3) Napojit na installer/deployer: ověřit před spuštěním / před vytvořením admina.
4) Přidat runtime kontroly pro kritické soubory (config + keys dir + generated), plus safe-mode.
5) Přidat out-of-band sentinel + monitoring/alerting šablony.
6) Marketplace/signers: extension dev dostanou signing keys a allowlist policy (governance).

