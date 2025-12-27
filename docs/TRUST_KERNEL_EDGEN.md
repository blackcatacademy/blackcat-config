# Trust Kernel runtime config — Edgen Chain (chain_id 4207)

Network:
- RPC: `https://rpc.layeredge.io`
- Explorer: `https://edgenscan.io`
- Chain ID: `4207`

## Runtime config template (JSON)

Create a runtime config file (recommended: `/etc/blackcat/config.json`) and fill it with at least:

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
      "mode": "root_uri",
      "contracts": {
        "instance_controller": "0xYOUR_INSTALL_INSTANCE_CONTROLLER_CLONE",
        "release_registry": "0x22681Ee2153B7B25bA6772B44c160BB60f4C333E"
      }
    }
  }
}
```

Notes:
- `trust.web3.contracts.instance_controller` must be the **per-install clone** address (not the implementation).
- `trust.web3.contracts.release_registry` is an optional **pin**; the source of truth is the on-chain pointer stored in the `InstanceController`.
- For production, prefer multiple RPC endpoints and `rpc_quorum >= 2` when available.
- `max_stale_sec=180` is the recommended strict default (after stale, runtime must fail closed).

## Policy v3: runtime config attestation (recommended)

If you use `TrustPolicyV3` in `InstanceController.activePolicyHash`, the kernel will also verify that the runtime config file is bound to the chain.

Compute the attestation key/value:

```bash
php vendor/bin/config runtime:attestation:runtime-config
# or
php vendor/bin/config runtime:attestation:runtime-config --path=/etc/blackcat/config.json
```

Then set `attestations[key]=value` on your per-install `InstanceController` and lock the key (recommended).

## Validate config (pre-boot)

```php
use BlackCat\Config\Runtime\Config;
use BlackCat\Config\Runtime\RuntimeConfigValidator;

Config::initFromFirstAvailableJsonFile();
RuntimeConfigValidator::assertTrustKernelWeb3Config(Config::repo());
```
