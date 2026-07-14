# Cloudflare observed-state collector

The collector is optional during installation. It performs read-only Cloudflare API requests and writes an observed-state JSON file for deterministic reconciliation.

Required environment variables:

```bash
export CLOUDFLARE_ACCOUNT_ID="..."
export CLOUDFLARE_API_TOKEN="..."
```

Run:

```bash
python3 -m atlas_resource_audit.cloudflare_collect --out /tmp/cloudflare-observed.json
```

The installer and test suite never call Cloudflare. Live collection is a separate operator action.
