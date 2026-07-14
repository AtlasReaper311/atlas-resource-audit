"""Read-only Cloudflare observed-state collector for Atlas resource audit."""
from __future__ import annotations
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

API_BASE = "https://api.cloudflare.com/client/v4"

class CloudflareError(RuntimeError):
    """Raised when Cloudflare returns an unusable response."""

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def request_json(path: str, token: str, query: dict[str, str] | None = None) -> dict[str, Any]:
    url = f"{API_BASE}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "AtlasReaper311/atlas-resource-audit",
    }, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise CloudflareError(f"Cloudflare HTTP {error.code} for {path}: {detail[:500]}") from error
    except urllib.error.URLError as error:
        raise CloudflareError(f"Cloudflare request failed for {path}: {error.reason}") from error
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise CloudflareError(f"Cloudflare returned invalid JSON for {path}") from error
    if not payload.get("success", False):
        raise CloudflareError(f"Cloudflare API reported failure for {path}: {payload.get('errors', [])}")
    return payload

def paged_results(path: str, token: str) -> list[dict[str, Any]]:
    page = 1
    results: list[dict[str, Any]] = []
    while True:
        payload = request_json(path, token, {"page": str(page), "per_page": "100"})
        page_results = payload.get("result", [])
        if not isinstance(page_results, list):
            raise CloudflareError(f"Cloudflare result for {path} was not a list")
        results.extend(page_results)
        total_pages = int((payload.get("result_info") or {}).get("total_pages") or 1)
        if page >= total_pages:
            return results
        page += 1

def as_resource(resource_type: str, item: dict[str, Any]) -> dict[str, Any]:
    resource_id = str(item.get("id") or item.get("uuid") or item.get("name") or "")
    name = str(item.get("title") or item.get("name") or resource_id)
    return {
        "type": resource_type,
        "id": resource_id,
        "name": name,
        "metadata": {key: item[key] for key in sorted(item) if key in {
            "created_on", "modified_on", "creation_date", "location", "jurisdiction"
        }},
    }

def collect_observed_state(account_id: str, token: str) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    endpoints = (
        ("kv-namespace", f"/accounts/{account_id}/storage/kv/namespaces"),
        ("d1-database", f"/accounts/{account_id}/d1/database"),
        ("r2-bucket", f"/accounts/{account_id}/r2/buckets"),
    )
    for resource_type, path in endpoints:
        for item in paged_results(path, token):
            resources.append(as_resource(resource_type, item))
    return {
        "schema_version": "atlas-resource-audit/observed-cloudflare/v1",
        "provider": "cloudflare",
        "account_id": account_id,
        "observed_at": utc_now(),
        "resources": sorted(resources, key=lambda item: (item["type"], item["name"], item["id"])),
    }

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect read-only Cloudflare resource state.")
    parser.add_argument("--account-id", default=os.environ.get("CLOUDFLARE_ACCOUNT_ID"))
    parser.add_argument("--token", default=os.environ.get("CLOUDFLARE_API_TOKEN"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if not args.account_id:
        parser.error("missing --account-id or CLOUDFLARE_ACCOUNT_ID")
    if not args.token:
        parser.error("missing --token or CLOUDFLARE_API_TOKEN")
    observed = collect_observed_state(args.account_id, args.token)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(observed, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote {len(observed['resources'])} Cloudflare resources to {args.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
