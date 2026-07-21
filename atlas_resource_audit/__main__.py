from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPORT_SCHEMA_VERSION = "atlas-resource-audit/report/v2"
DECLARED_SCHEMA_VERSION = "atlas-public-cloudflare-resources/v1"
OBSERVED_SCHEMA_VERSION = "atlas-resource-audit/observed-cloudflare/v2"
SUPPORTED_KINDS = ("d1-database", "kv-namespace", "r2-bucket")


class ResourceAuditError(ValueError):
    """Raised when declared or observed resource evidence is unusable."""


def load(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ResourceAuditError(f"{path} must contain a JSON object")
    return value


def _resource_key(item: dict[str, Any]) -> tuple[str, str]:
    return str(item.get("kind", "")), str(item.get("provider_id", ""))


def validate_declared(document: dict[str, Any]) -> list[dict[str, Any]]:
    if document.get("schema_version") != DECLARED_SCHEMA_VERSION:
        raise ResourceAuditError("declared resource registry schema is unsupported")
    if document.get("owner") != "AtlasReaper311/atlas-infra":
        raise ResourceAuditError("declared resource registry owner is not atlas-infra")
    account_id = document.get("account_id")
    if not isinstance(account_id, str) or not account_id:
        raise ResourceAuditError("declared resource registry account_id is missing")
    resources = document.get("resources")
    if not isinstance(resources, list):
        raise ResourceAuditError("declared resource registry resources must be an array")

    seen: set[tuple[str, str]] = set()
    validated: list[dict[str, Any]] = []
    for item in resources:
        if not isinstance(item, dict):
            raise ResourceAuditError("declared resource entries must be objects")
        kind, provider_id = _resource_key(item)
        if kind not in SUPPORTED_KINDS:
            raise ResourceAuditError(f"unsupported declared resource kind: {kind!r}")
        if not provider_id:
            raise ResourceAuditError("declared resource provider_id is missing")
        key = (kind, provider_id)
        if key in seen:
            raise ResourceAuditError(
                f"declared resource identity is duplicated: {kind}/{provider_id}"
            )
        seen.add(key)

        label = item.get("display_label")
        owner = item.get("owner")
        if not isinstance(label, str) or not label:
            raise ResourceAuditError(
                f"declared resource {kind}/{provider_id} has no display_label"
            )
        if not isinstance(owner, dict):
            raise ResourceAuditError(
                f"declared resource {kind}/{provider_id} has no owner"
            )
        service_id = owner.get("service_id")
        repository = owner.get("repository")
        if not isinstance(service_id, str) or not service_id:
            raise ResourceAuditError(
                f"declared resource {kind}/{provider_id} owner service_id is missing"
            )
        if not isinstance(repository, str) or not repository.startswith("AtlasReaper311/"):
            raise ResourceAuditError(
                f"declared resource {kind}/{provider_id} owner repository is invalid"
            )
        validated.append(item)

    return sorted(validated, key=lambda item: _resource_key(item))


def validate_observed(document: dict[str, Any]) -> list[dict[str, str]]:
    if document.get("schema_version") != OBSERVED_SCHEMA_VERSION:
        raise ResourceAuditError("observed Cloudflare document schema is unsupported")
    if document.get("provider") != "cloudflare":
        raise ResourceAuditError("observed resource provider is not cloudflare")
    account_id = document.get("account_id")
    if not isinstance(account_id, str) or not account_id:
        raise ResourceAuditError("observed resource account_id is missing")
    resources = document.get("resources")
    if not isinstance(resources, list):
        raise ResourceAuditError("observed resources must be an array")

    validated: list[dict[str, str]] = []
    for item in resources:
        if not isinstance(item, dict):
            raise ResourceAuditError("observed resource entries must be objects")
        if set(item) != {"kind", "provider_id"}:
            raise ResourceAuditError(
                "observed resource entries may contain only kind and provider_id"
            )
        kind, provider_id = _resource_key(item)
        if kind not in SUPPORTED_KINDS:
            raise ResourceAuditError(f"unsupported observed resource kind: {kind!r}")
        if not provider_id:
            raise ResourceAuditError("observed resource provider_id is missing")
        validated.append({"kind": kind, "provider_id": provider_id})
    return sorted(validated, key=lambda item: _resource_key(item))


def audit(declared: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    declared_resources = validate_declared(declared)
    observed_resources = validate_observed(observed)

    if declared["account_id"] != observed["account_id"]:
        raise ResourceAuditError(
            "declared and observed Cloudflare account identifiers do not match"
        )

    observed_keys = [_resource_key(item) for item in observed_resources]
    observed_key_set = set(observed_keys)
    duplicate_observed = sorted(
        key for key, count in Counter(observed_keys).items() if count > 1
    )

    findings: list[dict[str, Any]] = []
    declared_results: list[dict[str, Any]] = []
    declared_keys: set[tuple[str, str]] = set()
    declared_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    for item in declared_resources:
        key = _resource_key(item)
        declared_keys.add(key)
        declared_by_key[key] = item
        present = key in observed_key_set
        owner = item["owner"]
        result = {
            "kind": key[0],
            "provider_id": key[1],
            "display_label": item["display_label"],
            "owner": {
                "service_id": owner["service_id"],
                "repository": owner["repository"],
            },
            "state": "present" if present else "missing",
        }
        declared_results.append(result)
        if not present:
            findings.append(
                {
                    "severity": "error",
                    "type": "missing-public-resource",
                    "resource": result,
                    "summary": (
                        f"Declared public resource {key[0]}/{item['display_label']} "
                        "was not observed in the Cloudflare account."
                    ),
                }
            )

    for kind, provider_id in duplicate_observed:
        key = (kind, provider_id)
        declared_item = declared_by_key.get(key)
        if declared_item is not None:
            resource = {
                "kind": kind,
                "display_label": declared_item["display_label"],
                "publicly_declared": True,
            }
            summary = (
                f"Declared public resource {kind}/{declared_item['display_label']} "
                "was returned more than once by the provider observation."
            )
        else:
            resource = {"kind": kind, "publicly_declared": False}
            summary = (
                "An undeclared provider identity was returned more than once. "
                "Its identity is redacted because undeclared resources may be private."
            )
        findings.append(
            {
                "severity": "error",
                "type": "duplicate-provider-identity",
                "resource": resource,
                "summary": summary,
            }
        )

    observed_counts = Counter(kind for kind, _ in observed_keys)
    undeclared_counts = Counter(
        kind for kind, provider_id in observed_keys if (kind, provider_id) not in declared_keys
    )
    missing_count = sum(item["state"] == "missing" for item in declared_results)
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "failed" if findings else "healthy",
        "source": {
            "declared_schema_version": declared["schema_version"],
            "declared_owner": declared["owner"],
            "account_id": declared["account_id"],
            "observed_schema_version": observed["schema_version"],
            "observed_at": observed.get("observed_at"),
        },
        "privacy": {
            "model": "undeclared-provider-resources-are-aggregate-only",
            "note": (
                "Provider resources outside the public declaration may be private. "
                "Their identities are intentionally omitted from this report."
            ),
        },
        "summary": {
            "declared_resources": len(declared_results),
            "declared_present": len(declared_results) - missing_count,
            "declared_missing": missing_count,
            "observed_resources": len(observed_resources),
            "undeclared_observed_resources": sum(undeclared_counts.values()),
            "findings": len(findings),
        },
        "observed_counts": {
            kind: observed_counts.get(kind, 0) for kind in SUPPORTED_KINDS
        },
        "undeclared_observed_counts": {
            kind: undeclared_counts.get(kind, 0) for kind in SUPPORTED_KINDS
        },
        "declared_resources": declared_results,
        "findings": findings,
    }
    return report


def render(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Atlas public Cloudflare resource audit",
        "",
        f"Status: **{report['status'].upper()}**  ",
        f"Declared resources: **{summary['declared_resources']}**  ",
        f"Declared present: **{summary['declared_present']}**  ",
        f"Declared missing: **{summary['declared_missing']}**  ",
        f"Observed resources: **{summary['observed_resources']}**  ",
        f"Undeclared observed resources: **{summary['undeclared_observed_resources']}**",
        "",
        "> Undeclared provider resources may be private. Only aggregate counts are reported; their identities are not emitted.",
        "",
        "## Declared public resources",
        "",
        "| Kind | Label | Owner service | State |",
        "|---|---|---|---|",
    ]
    for item in report["declared_resources"]:
        lines.append(
            f"| `{item['kind']}` | `{item['display_label']}` | "
            f"`{item['owner']['service_id']}` | **{item['state']}** |"
        )

    lines.extend(["", "## Aggregate provider observation", ""])
    lines.append("| Kind | Observed | Undeclared aggregate |")
    lines.append("|---|---:|---:|")
    for kind in SUPPORTED_KINDS:
        lines.append(
            f"| `{kind}` | {report['observed_counts'][kind]} | "
            f"{report['undeclared_observed_counts'][kind]} |"
        )

    if report["findings"]:
        lines.extend(["", "## Findings", ""])
        for finding in report["findings"]:
            lines.append(f"- **{finding['type']}**: {finding['summary']}")
    else:
        lines.extend(["", "No declared public resource findings."])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile declared public Cloudflare resources against a read-only observation."
    )
    parser.add_argument("--declared", required=True)
    parser.add_argument("--observed", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--markdown-out")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    try:
        report = audit(load(args.declared), load(args.observed))
    except (OSError, json.JSONDecodeError, ResourceAuditError) as error:
        print(f"resource audit failed closed: {error}", file=sys.stderr)
        return 2

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if args.markdown_out:
        Path(args.markdown_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown_out).write_text(render(report), encoding="utf-8")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
