<div align="center">
  <img src="https://raw.githubusercontent.com/AtlasReaper311/AtlasReaper311/main/atlas-icon-dark-256.png" width="88" alt="Atlas Systems"/>
</div>

# atlas-resource-audit

```
┌─────────────────────────────────────────────┐
│  ATLAS SYSTEMS // atlas-resource-audit      │
│  reconcile public cloudflare storage        │
│  without exposing private account state     │
└─────────────────────────────────────────────┘
```

[![CI](https://github.com/AtlasReaper311/atlas-resource-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/AtlasReaper311/atlas-resource-audit/actions)
![Python](https://img.shields.io/badge/python-3.13-f5a623?style=flat-square&labelColor=0a0a0f)
![Boundary](https://img.shields.io/badge/provider-read--only-aaa9a0?style=flat-square&labelColor=0a0a0f)
![Cost](https://img.shields.io/badge/cost-%C2%A30-aaa9a0?style=flat-square&labelColor=0a0a0f)

Read-only desired-state versus observed-state reconciliation for the public Cloudflare storage owned by Atlas Systems. The auditor consumes the canonical public declaration from `atlas-infra`, performs minimum-identity provider reads, and reports missing declared resources without publishing the identities of undeclared account resources that may be private.

## The problem it solves

Cloudflare account discovery can see more than the public Atlas Systems estate. Treating every observed resource as public, or treating every undeclared resource as orphaned, would collapse the public/private boundary and could publish private infrastructure by accident.

The audit therefore separates two questions:

1. Is every resource intentionally declared as public still present in Cloudflare?
2. How many additional resources were observed by kind, without exposing who or what they belong to?

A declared resource that disappears is a failure. An undeclared provider resource is aggregate-only evidence and does not become a public identity merely because the read token can see it.

## Authority and data flow

The desired-state authority is:

```text
AtlasReaper311/atlas-infra
  policy/public-cloudflare-resources.json
```

That file declares public KV, D1, and R2 resources by `(kind, provider_id)`, with exactly one public owner and optional consumers. `atlas-resource-audit` does not maintain a second desired-state copy.

The scheduled flow is:

```text
atlas-infra public resource policy
              │
              ▼
    atlas-resource-audit
              │
              ├── read-only Cloudflare observation
              │      kind + provider_id only
              │
              ├── exact declared-resource reconciliation
              │
              └── sanitized JSON + Markdown report
                     │
                     ├── declared public identities
                     └── undeclared aggregate counts only
```

The raw Cloudflare observation is written under the GitHub runner temporary directory and removed at step exit. It is never uploaded as an artifact.

## Scheduled audit

`.github/workflows/audit.yml` runs every Monday at `07:41 UTC` and can also be started manually.

The job:

1. checks out this repository;
2. checks out `atlas-infra/main` read-only;
3. compiles and tests the deterministic audit engine;
4. reads the Cloudflare account ID from the canonical public policy;
5. collects KV, D1, and R2 identities using a read-only token;
6. reconciles the observed identities against the public declaration;
7. appends the sanitized Markdown report to the workflow summary;
8. retains only the sanitized JSON and Markdown reports for 30 days.

The workflow needs one GitHub Actions secret name:

```text
CF_RESOURCE_AUDIT_READ_TOKEN
```

The value is never committed or passed through chat. The Cloudflare token should have only the account-level read permissions required to list the approved resource families: KV storage read, D1 read, and R2 read. It does not need Worker deployment, route mutation, DNS mutation, storage write, or delete permissions.

If the secret is absent, the live step fails closed with an explicit configuration error rather than running a fixture-only audit and presenting it as live evidence.

## Usage

Run deterministic tests locally:

```bash
python3 -m compileall -q atlas_resource_audit tests
python3 -m unittest discover -s tests -v
```

Collect provider state with the credential supplied through the environment:

```bash
export CLOUDFLARE_ACCOUNT_ID="<public account id>"
export CLOUDFLARE_API_TOKEN="<read-only token>"
python3 -m atlas_resource_audit.cloudflare_collect \
  --out /tmp/cloudflare-observed.json
```

Run reconciliation against a checked-out Atlas Infra policy:

```bash
python3 -m atlas_resource_audit \
  --declared ../atlas-infra/policy/public-cloudflare-resources.json \
  --observed /tmp/cloudflare-observed.json \
  --json-out /tmp/resource-audit.json \
  --markdown-out /tmp/resource-audit.md
```

Delete the raw observed file after the run. Only the sanitized reports are suitable for publication or artifact retention.

## Report semantics

A healthy report means every declared public resource was observed exactly as declared and the observation contained no duplicate provider identity.

The report includes:

- total declared resources;
- declared present and missing counts;
- total observed counts by resource kind;
- undeclared observed counts by resource kind;
- public identity and owner for declared resources;
- explicit findings for missing declared resources or duplicate provider identities.

It intentionally does not include names, IDs, metadata, or inferred ownership for undeclared provider resources.

## Security boundary

The collector performs `GET` requests only. There is no provider write, delete, deploy, route, DNS, restore, or remediation path in this repository.

Observed provider entries are reduced immediately to:

```json
{
  "kind": "kv-namespace",
  "provider_id": "..."
}
```

The reconciliation layer may emit that identity only when it already appears in the canonical public Atlas Infra declaration. Tests assert that an undeclared provider ID cannot appear in either the JSON report or Markdown summary.

## How it fits into Atlas Systems

[`atlas-infra`](https://github.com/AtlasReaper311/atlas-infra) owns the public resource declaration and validates ownership; this repository performs the separate observed-state check. The result complements repository conformance and backup assurance without giving the auditor authority to repair Cloudflare state.

An infrastructure audit should be able to prove that declared public resources exist without turning provider visibility into publication authority.

---

Part of [atlas-systems.uk](https://atlas-systems.uk) · MIT License
