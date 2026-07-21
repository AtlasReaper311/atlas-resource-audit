# Cloudflare observed-state collector

## Purpose

The collector performs the provider-read half of the public resource audit. It lists Cloudflare KV namespaces, D1 databases, and R2 buckets for one account, then reduces every result to the minimum identity needed for reconciliation.

The output shape is `atlas-resource-audit/observed-cloudflare/v2`.

Each observed resource contains only:

```json
{
  "kind": "kv-namespace",
  "provider_id": "..."
}
```

Provider display names, timestamps, metadata, and inferred owners are intentionally discarded. Resources outside the public Atlas Infra declaration may be private, so their identities must never appear in retained reports.

## Credential

The collector reads:

```text
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_API_TOKEN
```

The account ID is public policy data and is read by the scheduled workflow from `AtlasReaper311/atlas-infra:policy/public-cloudflare-resources.json`.

The token is a GitHub Actions secret named `CF_RESOURCE_AUDIT_READ_TOKEN`. Enter its value only through the approved GitHub or Cloudflare secret-management interface. Do not commit it, pass it as a workflow input, place it in command arguments, or write it to logs.

The required Cloudflare API token permissions are:

- `Workers KV Storage Read`;
- `D1 Read`;
- `Workers R2 Storage Read`.

No write permission is required.

## Provider pagination

The Cloudflare APIs do not share one pagination shape:

- KV namespaces use page-based array results;
- D1 databases use page-based array results;
- R2 buckets return a `result.buckets` object and use a continuation cursor.

The collector implements those contracts separately and fails closed on an unexpected response shape or repeated R2 cursor.

## Local operator run

Derive the account ID from a neighbouring `atlas-infra` checkout:

```bash
export CLOUDFLARE_ACCOUNT_ID="$(python3 -c 'import json; print(json.load(open("../atlas-infra/policy/public-cloudflare-resources.json", encoding="utf-8"))["account_id"])')"
test -n "${CLOUDFLARE_API_TOKEN:-}"
python3 -m atlas_resource_audit.cloudflare_collect \
  --out /tmp/cloudflare-observed.json
```

Supply `CLOUDFLARE_API_TOKEN` through the approved local secret-injection method before the command. The observed file is sensitive operator evidence even though it contains only provider IDs. Use it as a temporary input to the reconciler and delete it after the run.

## Scheduled run

`.github/workflows/audit.yml` checks out `atlas-infra/main`, reads the canonical account ID, collects the temporary observation under `${RUNNER_TEMP}`, reconciles it, and uploads only sanitized JSON and Markdown reports.

The workflow never uploads the raw observation.

## Failure model

The collector fails closed when:

- the account ID is missing;
- the token is missing;
- Cloudflare returns an HTTP or API error;
- a provider response is not valid JSON;
- a resource has no stable identity;
- page or cursor pagination returns an unusable result shape;
- R2 pagination repeats a cursor.

A failed collection does not produce a healthy audit result.
