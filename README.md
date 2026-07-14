# atlas-resource-audit

Read-only desired-state versus observed-state reconciliation for Cloudflare KV, D1, and R2 resources. It reports orphaned, missing, and multiply-owned resources.

```bash
python -m atlas_resource_audit --manifest estate.manifest.json --bindings bindings.json --observed cloudflare.json --json-out report.json --markdown-out summary.md
```

The collector is intentionally separate from the deterministic audit engine. Produce `cloudflare.json` with Wrangler or the Cloudflare API using a read-only token. No deletion path exists.
