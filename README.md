<div align="center">
  <img src="https://raw.githubusercontent.com/AtlasReaper311/AtlasReaper311/main/atlas-icon-dark-256.png" width="88" alt="Atlas Systems"/>
</div>

# atlas-resource-audit

```
┌─────────────────────────────────────────────┐
│  ATLAS SYSTEMS // atlas-resource-audit      │
│  reconcile public cloudflare topology       │
│  without exposing private account state     │
└─────────────────────────────────────────────┘
```

[![CI](https://github.com/AtlasReaper311/atlas-resource-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/AtlasReaper311/atlas-resource-audit/actions)
![Python](https://img.shields.io/badge/python-3.13-f5a623?style=flat-square&labelColor=0a0a0f)
![Boundary](https://img.shields.io/badge/provider-read--only-aaa9a0?style=flat-square&labelColor=0a0a0f)
![Cost](https://img.shields.io/badge/cost-%C2%A30-aaa9a0?style=flat-square&labelColor=0a0a0f)

Read-only desired-state versus observed-state reconciliation for public Cloudflare storage and runtime topology owned by Atlas Systems. The auditor consumes canonical declarations from `atlas-infra`, performs minimum-identity provider reads, and reports missing or drifting declared resources without publishing the identities of undeclared account objects that may be private.

## The problem it solves

Cloudflare account discovery can see more than the public Atlas Systems estate. Treating every observed object as public, or treating every undeclared object as orphaned, would collapse the public/private boundary and could publish private infrastructure by accident.

The audit therefore separates two questions:

1. Is every resource intentionally declared as public still present and wired as expected in Cloudflare?
2. How many additional provider objects were observed, without exposing who or what they belong to?

A declared resource that disappears or changes ownership is a finding. An undeclared provider object is aggregate-only evidence and does not become a public identity merely because the read token can see it.

## Authority and data flow

The desired-state authorities are:

```text
AtlasReaper311/atlas-infra
  policy/public-cloudflare-resources.json
  policy/public-cloudflare-topology.json
```

The resource policy owns public KV, D1, and R2 identities. The topology policy owns the explicit public allowlist for Worker scripts, routes, service bindings, metadata endpoints, and Pages projects. `atlas-resource-audit` does not maintain a second desired-state copy.

The retained evidence flow is:

```text
atlas-infra public declarations
              │
              ▼
    atlas-resource-audit
              │
              ├── read-only Cloudflare observation
              │
              ├── immediate privacy reduction
              │
              ├── deterministic reconciliation
              │
              └── sanitized JSON + Markdown reports
                     │
                     ├── declared public identities
                     └── undeclared aggregate counts only
```

Raw provider responses are never uploaded as artifacts. Topology settings are reduced in memory before output, and secret-bearing Worker binding values are not part of the retained topology schema.

## Scheduled storage audit

`.github/workflows/audit.yml` runs every Monday at `07:41 UTC` and can also be started manually.

The job:

1. checks out this repository;
2. checks out `atlas-infra/main` read-only;
3. compiles and tests the deterministic audit engine;
4. reads the Cloudflare account ID from the canonical public resource policy;
5. collects KV, D1, and R2 identities using a read-only token;
6. reconciles the observed identities against the public declaration;
7. appends the sanitized Markdown report to the workflow summary;
8. retains only the sanitized JSON and Markdown reports for 30 days.

The workflow needs one GitHub Actions secret name:

```text
CF_RESOURCE_AUDIT_READ_TOKEN
```

The value is never committed or passed through chat. The existing storage audit requires only the account-level permissions needed for KV, D1, and R2 reads. It does not need Worker deployment, route mutation, DNS mutation, storage write, or delete permissions.

If the secret is absent, the live step fails closed with an explicit configuration error rather than running a fixture-only audit and presenting it as live evidence.

### Disabled provider features

Provider capability is interpreted against the canonical declaration, not treated as a reason to enable unused products.

Cloudflare R2 error `10042` (`NotEntitled`) is accepted as an empty R2 observation only when the checked-out Atlas Infra declaration contains no `r2-bucket` resources. If any public R2 bucket is declared, or if the collector is run without declaration context, the same provider response remains a hard failure.

This keeps the audit fail-closed for resources Atlas Systems claims to own while allowing an intentionally unused Cloudflare product to remain disabled.

## Usage

Run deterministic tests locally:

```bash
python3 -m compileall -q atlas_resource_audit tests
python3 -m unittest discover -s tests -v
```

For an operator storage collection, check out `atlas-infra` beside this repository and derive the public account ID from policy:

```bash
export CLOUDFLARE_ACCOUNT_ID="$(python3 -c 'import json; print(json.load(open("../atlas-infra/policy/public-cloudflare-resources.json", encoding="utf-8"))["account_id"])')"
test -n "${CLOUDFLARE_API_TOKEN:-}"
python3 -m atlas_resource_audit.cloudflare_collect \
  --declared ../atlas-infra/policy/public-cloudflare-resources.json \
  --out /tmp/cloudflare-observed.json
```

Supply `CLOUDFLARE_API_TOKEN` through the approved local secret-injection method before running that command. Do not place the token in source, shell history, command arguments, chat, or issue text.

Run storage reconciliation:

```bash
python3 -m atlas_resource_audit \
  --declared ../atlas-infra/policy/public-cloudflare-resources.json \
  --observed /tmp/cloudflare-observed.json \
  --json-out /tmp/resource-audit.json \
  --markdown-out /tmp/resource-audit.md
```

Delete the raw observed file after the run. Only the sanitized reports are suitable for publication or artifact retention.

## Live topology reconciliation

`.github/workflows/topology-audit.yml` is deliberately manual-only. Merging the source does not start a provider read.

The topology collector reads the exact public declaration from the merged Atlas Infra authority and observes:

- deployed Worker script existence;
- Worker routes;
- service and declared storage bindings for declared public Workers;
- the bounded public `/_meta` identity for declared Workers;
- declared public Cloudflare Pages projects.

Account-wide Worker, route, and Pages discovery is reduced before retention. Undeclared Worker names, route patterns, Pages project names, and binding identities never enter the sanitized observation or final report. Only aggregate undeclared counts survive.

Worker settings are queried only for declared public Worker scripts. The collector accepts only the bounded binding types needed for topology reconciliation. Secret-text bindings and all unsupported provider binding payloads are discarded.

The topology report can produce findings including:

- `declared-but-not-observed`;
- `observed-but-undeclared` as a redacted aggregate;
- `route-owner-drift`;
- `missing-service-binding`;
- `unexpected-service-binding`;
- `metadata-identity-mismatch`;
- `missing-storage`;
- `orphaned-storage`;
- `observed-state-unavailable`.

No remediation path exists. A finding cannot deploy, delete, bind, unbind, archive, edit DNS, change routes, modify Pages, or mutate storage.

The manual topology workflow intentionally reuses the existing `CF_RESOURCE_AUDIT_READ_TOKEN` secret name. A live topology run requires that token to have the additional provider read permissions needed for Worker scripts/settings, Worker routes, Pages projects, and zone discovery. Changing token permissions is a separate approved provider action and is not performed by this repository change.

## Report semantics

A healthy storage report means every declared public storage resource was observed exactly as declared and the observation contained no duplicate provider identity.

A healthy topology report means every declared public Worker and Pages project was observed, declared routes and bindings matched, and each available metadata endpoint identified the expected public service.

An unavailable binding or metadata observation is represented as unavailable. It is never silently converted to healthy evidence.

Both report families intentionally omit names, IDs, metadata, or inferred ownership for undeclared provider objects.

## Security boundary

Collectors perform `GET` requests only. There is no provider write, delete, deploy, route, DNS, restore, or remediation path in this repository.

Storage observations are reduced immediately to:

```json
{
  "kind": "kv-namespace",
  "provider_id": "..."
}
```

Topology observations retain declared public identities only. Tests inject private-looking Worker, route, and Pages identities plus secret-text binding payloads and assert that they cannot appear in retained topology evidence.

## How it fits into Atlas Systems

[`atlas-infra`](https://github.com/AtlasReaper311/atlas-infra) owns the public storage and topology declarations and validates their ownership; this repository performs the separate observed-state checks. The result gives Atlas Trace a bounded live-evidence source without giving the auditor authority to repair Cloudflare state.

An infrastructure audit should be able to prove that declared public resources exist without turning provider visibility into publication authority.

---

Part of [atlas-systems.uk](https://atlas-systems.uk) · MIT License
