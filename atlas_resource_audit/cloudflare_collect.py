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
from pathlib import Path
from typing import Any

API_BASE = "https://api.cloudflare.com/client/v4"
OBSERVED_SCHEMA_VERSION = "atlas-resource-audit/observed-cloudflare/v2"
R2_NOT_ENTITLED_CODE = 10042


class CloudflareError(RuntimeError):
    """Raised when Cloudflare returns an unusable response."""


class CloudflareAPIError(CloudflareError):
    """Structured Cloudflare API failure with provider error codes preserved."""

    def __init__(
        self,
        path: str,
        errors: list[dict[str, Any]],
        *,
        http_status: int | None = None,
    ) -> None:
        self.path = path
        self.errors = tuple(errors)
        self.http_status = http_status
        status = f"HTTP {http_status}" if http_status is not None else "API failure"
        super().__init__(f"Cloudflare {status} for {path}: {errors}")

    def has_code(self, code: int) -> bool:
        """Return whether any structured provider error carries ``code``."""

        return any(error.get("code") == code for error in self.errors)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _structured_errors(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return []
    return [error for error in errors if isinstance(error, dict)]


def request_json(
    path: str, token: str, query: dict[str, str] | None = None
) -> dict[str, Any]:
    url = f"{API_BASE}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "AtlasReaper311/atlas-resource-audit",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(detail)
        except json.JSONDecodeError:
            payload = None
        errors = _structured_errors(payload)
        if errors:
            raise CloudflareAPIError(
                path,
                errors,
                http_status=error.code,
            ) from error
        raise CloudflareError(
            f"Cloudflare HTTP {error.code} for {path}: {detail[:500]}"
        ) from error
    except urllib.error.URLError as error:
        raise CloudflareError(
            f"Cloudflare request failed for {path}: {error.reason}"
        ) from error
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise CloudflareError(f"Cloudflare returned invalid JSON for {path}") from error
    if not payload.get("success", False):
        errors = _structured_errors(payload)
        if errors:
            raise CloudflareAPIError(path, errors)
        raise CloudflareError(
            f"Cloudflare API reported failure for {path}: {payload.get('errors', [])}"
        )
    return payload


def paged_array_results(
    path: str, token: str, *, per_page: int = 1000
) -> list[dict[str, Any]]:
    """Collect a Cloudflare v4 array result that uses page-based pagination."""

    page = 1
    results: list[dict[str, Any]] = []
    while True:
        payload = request_json(
            path, token, {"page": str(page), "per_page": str(per_page)}
        )
        page_results = payload.get("result", [])
        if not isinstance(page_results, list):
            raise CloudflareError(f"Cloudflare result for {path} was not a list")
        results.extend(item for item in page_results if isinstance(item, dict))

        result_info = payload.get("result_info") or {}
        if not isinstance(result_info, dict):
            raise CloudflareError(f"Cloudflare result_info for {path} was not an object")
        total_pages = result_info.get("total_pages")
        if isinstance(total_pages, int) and page < total_pages:
            page += 1
            continue
        total_count = result_info.get("total_count")
        if isinstance(total_count, int) and len(results) < total_count:
            page += 1
            continue
        if len(page_results) >= per_page and total_count is None and total_pages is None:
            page += 1
            continue
        return results


def r2_bucket_results(
    path: str, token: str, *, per_page: int = 1000
) -> list[dict[str, Any]]:
    """Collect R2 buckets using the cursor pagination defined by the R2 API."""

    cursor: str | None = None
    results: list[dict[str, Any]] = []
    seen_cursors: set[str] = set()
    while True:
        query = {"per_page": str(per_page)}
        if cursor:
            query["cursor"] = cursor
        payload = request_json(path, token, query)
        result = payload.get("result") or {}
        if not isinstance(result, dict):
            raise CloudflareError(f"Cloudflare R2 result for {path} was not an object")
        buckets = result.get("buckets") or []
        if not isinstance(buckets, list):
            raise CloudflareError(f"Cloudflare R2 buckets for {path} were not a list")
        results.extend(item for item in buckets if isinstance(item, dict))

        result_info = payload.get("result_info") or {}
        if not isinstance(result_info, dict):
            raise CloudflareError(f"Cloudflare R2 result_info for {path} was not an object")
        next_cursor = result_info.get("cursor")
        if not isinstance(next_cursor, str) or not next_cursor:
            return results
        if next_cursor in seen_cursors:
            raise CloudflareError("Cloudflare R2 pagination repeated a cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor


def as_resource(kind: str, item: dict[str, Any]) -> dict[str, str]:
    """Return the minimum identity needed for reconciliation.

    Names and provider metadata are intentionally excluded because undeclared
    account resources may be private. R2 does not expose a separate bucket ID,
    so its bucket name is the stable provider identity used by the API.
    """

    provider_id = str(item.get("id") or item.get("uuid") or item.get("name") or "")
    if not provider_id:
        raise CloudflareError(f"Cloudflare {kind} result has no stable identity")
    return {"kind": kind, "provider_id": provider_id}


def load_declared_kinds(path: str | Path, account_id: str) -> set[str]:
    """Load declared resource kinds and verify the policy targets this account."""

    try:
        with open(path, encoding="utf-8") as handle:
            declared = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise CloudflareError(f"cannot load declared resource policy {path}: {error}") from error

    if not isinstance(declared, dict):
        raise CloudflareError("declared resource policy must be a JSON object")
    if declared.get("account_id") != account_id:
        raise CloudflareError("declared resource policy account_id does not match collector account")
    resources = declared.get("resources")
    if not isinstance(resources, list):
        raise CloudflareError("declared resource policy resources must be an array")

    kinds: set[str] = set()
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("kind"), str):
            raise CloudflareError("declared resource policy contains a resource without a kind")
        kinds.add(resource["kind"])
    return kinds


def collect_observed_state(
    account_id: str,
    token: str,
    *,
    declared_kinds: set[str] | None = None,
) -> dict[str, Any]:
    """Collect minimum Cloudflare identities with policy-aware feature handling.

    A provider feature being disabled is not equivalent to a collection failure
    when the canonical declaration contains no resources of that kind. The only
    currently supported exception is Cloudflare R2 error 10042 (NotEntitled).
    Without declaration context, or when an R2 bucket is declared, the collector
    remains fail-closed.
    """

    resources: list[dict[str, str]] = []

    for kind, path in (
        ("kv-namespace", f"/accounts/{account_id}/storage/kv/namespaces"),
        ("d1-database", f"/accounts/{account_id}/d1/database"),
    ):
        for item in paged_array_results(path, token):
            resources.append(as_resource(kind, item))

    r2_path = f"/accounts/{account_id}/r2/buckets"
    try:
        r2_items = r2_bucket_results(r2_path, token)
    except CloudflareAPIError as error:
        r2_is_undeclared = (
            declared_kinds is not None and "r2-bucket" not in declared_kinds
        )
        if not (error.has_code(R2_NOT_ENTITLED_CODE) and r2_is_undeclared):
            raise
        r2_items = []

    for item in r2_items:
        resources.append(as_resource("r2-bucket", item))

    return {
        "schema_version": OBSERVED_SCHEMA_VERSION,
        "provider": "cloudflare",
        "account_id": account_id,
        "observed_at": utc_now(),
        "resources": sorted(
            resources, key=lambda item: (item["kind"], item["provider_id"])
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect minimum read-only Cloudflare resource identities."
    )
    parser.add_argument("--account-id", default=os.environ.get("CLOUDFLARE_ACCOUNT_ID"))
    parser.add_argument("--token", default=os.environ.get("CLOUDFLARE_API_TOKEN"))
    parser.add_argument(
        "--declared",
        help="canonical public resource declaration used for fail-closed feature handling",
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if not args.account_id:
        parser.error("missing --account-id or CLOUDFLARE_ACCOUNT_ID")
    if not args.token:
        parser.error("missing --token or CLOUDFLARE_API_TOKEN")

    try:
        declared_kinds = (
            load_declared_kinds(args.declared, args.account_id)
            if args.declared
            else None
        )
        observed = collect_observed_state(
            args.account_id,
            args.token,
            declared_kinds=declared_kinds,
        )
    except CloudflareError as error:
        print(f"Cloudflare collection failed: {error}", file=sys.stderr)
        return 2

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(observed, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"observed {len(observed['resources'])} Cloudflare resources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
