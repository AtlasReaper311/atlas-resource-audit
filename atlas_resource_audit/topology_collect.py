"""Read-only Cloudflare topology collector with fail-closed publication rules.

Provider discovery may observe private account objects. This module never emits
those identities. It reduces account-wide discovery to declared public objects
plus aggregate undeclared counts before any document is written.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atlas_resource_audit.cloudflare_collect import CloudflareError, request_json

OBSERVED_SCHEMA_VERSION = "atlas-resource-audit/observed-topology/v1"
DECLARED_SCHEMA_VERSION = "atlas-public-cloudflare-topology/v1"
SAFE_BINDING_TYPES = {
    "service",
    "kv_namespace",
    "d1",
    "r2_bucket",
    "durable_object_namespace",
}


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def load_declared(path: str | Path) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CloudflareError(f"cannot load topology declaration {path}: {error}") from error
    if not isinstance(document, dict):
        raise CloudflareError("topology declaration must be a JSON object")
    if document.get("schema_version") != DECLARED_SCHEMA_VERSION:
        raise CloudflareError("unsupported topology declaration schema")
    if document.get("owner") != "AtlasReaper311/atlas-infra":
        raise CloudflareError("topology declaration owner is not atlas-infra")
    if not isinstance(document.get("workers"), list):
        raise CloudflareError("topology declaration workers must be an array")
    if not isinstance(document.get("pages_projects"), list):
        raise CloudflareError("topology declaration pages_projects must be an array")
    return document


def _array_result(path: str, token: str) -> list[dict[str, Any]]:
    payload = request_json(path, token)
    result = payload.get("result")
    if not isinstance(result, list):
        raise CloudflareError(f"Cloudflare result for {path} was not a list")
    return [item for item in result if isinstance(item, dict)]


def _paged_projects(path: str, token: str) -> list[dict[str, Any]]:
    page = 1
    projects: list[dict[str, Any]] = []
    while True:
        payload = request_json(path, token, {"page": str(page), "per_page": "100"})
        result = payload.get("result")
        if not isinstance(result, list):
            raise CloudflareError(f"Cloudflare result for {path} was not a list")
        projects.extend(item for item in result if isinstance(item, dict))
        info = payload.get("result_info") or {}
        if not isinstance(info, dict):
            raise CloudflareError(f"Cloudflare result_info for {path} was not an object")
        total_pages = info.get("total_pages")
        if isinstance(total_pages, int) and page < total_pages:
            page += 1
            continue
        if len(result) == 100 and total_pages is None:
            page += 1
            continue
        return projects


def _safe_binding(binding: dict[str, Any]) -> dict[str, Any] | None:
    """Reduce one Worker binding to non-secret topology fields only."""
    binding_type = binding.get("type")
    name = binding.get("name")
    if binding_type not in SAFE_BINDING_TYPES or not isinstance(name, str):
        return None
    if binding_type == "service":
        service = binding.get("service")
        if not isinstance(service, str):
            return None
        return {"binding": name, "kind": "service", "target": service}
    if binding_type == "kv_namespace":
        target = binding.get("namespace_id") or binding.get("id")
        if not isinstance(target, str):
            return None
        return {"binding": name, "kind": "kv-namespace", "target": target}
    if binding_type == "d1":
        target = binding.get("id") or binding.get("database_id")
        if not isinstance(target, str):
            return None
        return {"binding": name, "kind": "d1-database", "target": target}
    if binding_type == "r2_bucket":
        target = binding.get("bucket_name") or binding.get("name")
        if not isinstance(target, str):
            return None
        return {"binding": name, "kind": "r2-bucket", "target": target}
    if binding_type == "durable_object_namespace":
        class_name = binding.get("class_name")
        if not isinstance(class_name, str):
            return None
        return {"binding": name, "kind": "durable-object", "target": class_name}
    return None


def _settings_bindings(account_id: str, script: str, token: str) -> tuple[str, list[dict[str, Any]]]:
    path = f"/accounts/{account_id}/workers/scripts/{script}/settings"
    try:
        payload = request_json(path, token)
    except CloudflareError:
        return "unavailable", []
    result = payload.get("result")
    if not isinstance(result, dict):
        return "unavailable", []
    bindings = result.get("bindings")
    if not isinstance(bindings, list):
        return "unavailable", []
    reduced = []
    for item in bindings:
        if not isinstance(item, dict):
            continue
        safe = _safe_binding(item)
        if safe is not None:
            reduced.append(safe)
    reduced.sort(key=lambda item: (item["kind"], item["binding"], item["target"]))
    return "observed", reduced


def _metadata(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "AtlasReaper311/atlas-resource-audit"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return {"state": "unavailable"}
    if not isinstance(payload, dict):
        return {"state": "unavailable"}
    result: dict[str, Any] = {"state": "observed"}
    for key in ("name", "version", "status"):
        value = payload.get(key)
        if isinstance(value, str) and len(value) <= 160:
            result[key] = value
    return result


def collect_observed_topology(declared: dict[str, Any], token: str) -> dict[str, Any]:
    account_id = declared.get("account_id")
    zone_id = declared.get("zone_id")
    if not isinstance(account_id, str) or not isinstance(zone_id, str):
        raise CloudflareError("topology declaration is missing account_id or zone_id")

    scripts = _array_result(f"/accounts/{account_id}/workers/scripts", token)
    routes = _array_result(f"/zones/{zone_id}/workers/routes", token)
    pages = _paged_projects(f"/accounts/{account_id}/pages/projects", token)

    declared_workers = {
        item["script_name"]: item
        for item in declared["workers"]
        if isinstance(item, dict) and isinstance(item.get("script_name"), str)
    }
    declared_pages = {
        item["project_name"]: item
        for item in declared["pages_projects"]
        if isinstance(item, dict) and isinstance(item.get("project_name"), str)
    }

    observed_script_names = {
        item.get("id") for item in scripts if isinstance(item.get("id"), str)
    }
    observed_page_names = {
        item.get("name") for item in pages if isinstance(item.get("name"), str)
    }

    routes_for_public: dict[str, list[str]] = {name: [] for name in declared_workers}
    undeclared_route_count = 0
    for route in routes:
        script = route.get("script")
        pattern = route.get("pattern")
        if script in declared_workers and isinstance(pattern, str):
            routes_for_public[script].append(pattern)
        else:
            undeclared_route_count += 1

    workers: list[dict[str, Any]] = []
    for script, item in sorted(declared_workers.items()):
        present = script in observed_script_names
        bindings_state = "not-observed"
        bindings: list[dict[str, Any]] = []
        metadata = {"state": "not-observed"}
        if present:
            bindings_state, bindings = _settings_bindings(account_id, script, token)
            metadata = _metadata(item["metadata_url"])
        workers.append(
            {
                "script_name": script,
                "observed": present,
                "routes": sorted(set(routes_for_public.get(script, []))),
                "bindings_state": bindings_state,
                "bindings": bindings,
                "metadata": metadata,
            }
        )

    projects = [
        {"project_name": name, "observed": name in observed_page_names}
        for name in sorted(declared_pages)
    ]

    return {
        "schema_version": OBSERVED_SCHEMA_VERSION,
        "provider": "cloudflare",
        "account_id": account_id,
        "zone_id": zone_id,
        "observed_at": utc_now(),
        "privacy": {
            "model": "declared-public-identities-plus-aggregate-undeclared-counts",
            "raw_provider_payload_retained": False,
        },
        "aggregate_counts": {
            "workers_total": len(observed_script_names),
            "workers_undeclared": len(observed_script_names - set(declared_workers)),
            "routes_total": len(routes),
            "routes_undeclared_or_private": undeclared_route_count,
            "pages_total": len(observed_page_names),
            "pages_undeclared": len(observed_page_names - set(declared_pages)),
        },
        "workers": workers,
        "pages_projects": projects,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect privacy-safe read-only Cloudflare topology evidence.")
    parser.add_argument("--declared", required=True)
    parser.add_argument("--token", default=os.environ.get("CLOUDFLARE_API_TOKEN"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if not args.token:
        parser.error("missing --token or CLOUDFLARE_API_TOKEN")
    try:
        declared = load_declared(args.declared)
        observed = collect_observed_topology(declared, args.token)
    except CloudflareError as error:
        print(f"Cloudflare topology collection failed: {error}", file=sys.stderr)
        return 2
    Path(args.out).write_text(
        json.dumps(observed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("topology observation written with undeclared identities redacted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
