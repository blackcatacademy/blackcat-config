# Config Hub – Roadmap

## Stage 1 – Foundation ✅
- Loader agreguje defaults + profiles a exponuje CLI (`profile:*`, `integration:*`, `security:*`, `telemetry:*`).
- `profiles.php` obsahuje dev/staging/prod profile + env šablony, telemetry a integrace na installer/database/messaging/governance.
- Telemetry (.ndjson) a smoke test (`php tests/ProfileConfigTest.php`) drží dohled, `bin/config check` běží security/integration checklist.

## Stage 2 – Installer Integration
- generovat `installer.yaml`/env overlay pro `blackcat-installer` a `blackcat-deployer`.
- CLI příkaz `installer:plan` popíše změny mezi profily (diff env/proměnných).
- telemetry feed posílat do `blackcat-observability`.

## Stage 3 – Secrets Management (Vault integration)
- definovat secret backends, mapping role-id/tokenů, CLI pro seeding secret store.
- `security:check` validuje napojení na Vault/KMS a audituje secret placeholders.

## Stage 4 – Cross-Ecosystem Automation
- Wire blackcat-config services into installer/orchestrator pipelines for push-button deployments.
- Expand contract tests covering dependencies listed in ECOSYSTEM.md.
- Publish metrics/controls so observability, security, and governance repos can reason about blackcat-config automatically.

## Stage 5 – Continuous AI Augmentation
- Ship AI-ready manifests/tutorials enabling GPT installers to compose blackcat-config stacks autonomously.
- Add self-healing + policy feedback loops leveraging blackcat-agent, blackcat-governance, and marketplace signals.
- Feed anonymized adoption data to blackcat-usage and reward contributors via blackcat-payout.
