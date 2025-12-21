# Config Hub – Roadmap

## Stage 1 – Foundation ✅
- Loader aggregates defaults + profiles and exposes CLI (`profile:*`, `integration:*`, `security:*`, `telemetry:*`).
- `profiles.php` includes dev/staging/prod profiles + env templates, telemetry, and integrations for installer/database/messaging/governance.
- Telemetry (.ndjson) and smoke test (`php tests/ProfileConfigTest.php`) keep baseline coverage; `bin/config check` runs security/integration checklists.

## Stage 2 – Installer Integration
- Generate `installer.yaml` / env overlays for `blackcat-installer` and `blackcat-deployer`.
- CLI command `installer:plan` describes changes between profiles (env variable diff).
- Send telemetry feed into `blackcat-observability`.

## Stage 3 – Secrets Management (Vault integration)
- Define secret backends, map role-id/tokens, and provide CLI for seeding the secret store.
- `security:check` validates Vault/KMS integration and audits secret placeholders.

## Stage 4 – Cross-Ecosystem Automation
- Wire blackcat-config services into installer/orchestrator pipelines for push-button deployments.
- Expand contract tests covering dependencies listed in ECOSYSTEM.md.
- Publish metrics/controls so observability, security, and governance repos can reason about blackcat-config automatically.

## Stage 5 – Trust & Integrity (Supply Chain)
- Signed integrity manifests (checksums + signatures) for official releases.
- Installer/deployer gates: refuse to enable traffic on mismatch.
- Runtime safe-mode on detected tampering (no silent bypass).
- Out-of-band watchdog/sentinel integration (monitoring/alerting).

## Stage 6 – Continuous AI Augmentation
- Ship AI-ready manifests/tutorials enabling GPT installers to compose blackcat-config stacks autonomously.
- Add self-healing + policy feedback loops leveraging blackcat-agent, blackcat-governance, and marketplace signals.
- Feed anonymized adoption data to blackcat-usage and reward contributors via blackcat-payout.
