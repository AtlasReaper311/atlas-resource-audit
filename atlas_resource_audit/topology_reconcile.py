"""Deterministic public Cloudflare topology reconciliation.

The input observation is already privacy-reduced. This layer may emit declared
public identities and aggregate undeclared counts, but it never accepts raw
provider account payloads as publication authority.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DECLARED_SCHEMA_VERSION = "atlas-public-cloudflare-topology/v1"
OBSERVED_SCHEMA_VERSION = "atlas-resource-audit/observed-topology/v1"
REPORT_SCHEMA_VERSION = "atlas-resource-audit/topology-report/v1"


class TopologyAuditError(ValueError):
    """Declared or observed topology evidence is unusable."""


def load(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TopologyAuditError(f"{path} must contain a JSON object")
    return value


def _expected_bindings(worker: dict[str, Any]) -> set[tuple[str, str, str]]:
    expected: set[tuple[str, str, str]] = set()
    for binding in worker.get("service_bindings", []):
        expected.add(("service", binding["binding"], binding["service"]))
    for binding in worker.get("storage_bindings", []):
        target = binding.get("provider_id") or binding.get("class_name")
        expected.add((binding["kind"], binding["binding"], target))
    return expected


def _observed_bindings(worker: dict[str, Any]) -> set[tuple[str, str, str]]:
    result: set[tuple[str, str, str]] = set()
    for binding in worker.get("bindings", []):
        if not isinstance(binding, dict):
            continue
        kind = binding.get("kind")
        name = binding.get("binding")
        target = binding.get("target")
        if all(isinstance(value, str) for value in (kind, name, target)):
            result.add((kind, name, target))
    return result


def reconcile(declared: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    if declared.get("schema_version") != DECLARED_SCHEMA_VERSION:
        raise TopologyAuditError("unsupported declared topology schema")
    if observed.get("schema_version") != OBSERVED_SCHEMA_VERSION:
        raise TopologyAuditError("unsupported observed topology schema")
    if declared.get("account_id") != observed.get("account_id"):
        raise TopologyAuditError("declared and observed Cloudflare account ids differ")
    if declared.get("zone_id") != observed.get("zone_id"):
        raise TopologyAuditError("declared and observed Cloudflare zone ids differ")
    privacy = observed.get("privacy")
    if not isinstance(privacy, dict) or privacy.get("raw_provider_payload_retained") is not False:
        raise TopologyAuditError("observed topology does not prove raw provider payload redaction")

    declared_workers = {
        worker["script_name"]: worker
        for worker in declared.get("workers", [])
        if isinstance(worker, dict) and isinstance(worker.get("script_name"), str)
    }
    observed_workers = {
        worker["script_name"]: worker
        for worker in observed.get("workers", [])
        if isinstance(worker, dict) and isinstance(worker.get("script_name"), str)
    }
    if set(observed_workers) != set(declared_workers):
        raise TopologyAuditError("observed document must contain exactly the declared public Worker identities")

    findings: list[dict[str, Any]] = []
    worker_results: list[dict[str, Any]] = []

    def add(severity: str, finding_type: str, subject: str, summary: str) -> None:
        findings.append(
            {
                "severity": severity,
                "type": finding_type,
                "subject": subject,
                "summary": summary,
            }
        )

    for script in sorted(declared_workers):
        expected = declared_workers[script]
        actual = observed_workers[script]
        state = "healthy"
        if actual.get("observed") is not True:
            state = "failed"
            add("error", "declared-but-not-observed", script, "Declared public Worker was not observed in Cloudflare.")
        else:
            expected_routes = {route["pattern"] for route in expected.get("routes", [])}
            observed_routes = {
                route for route in actual.get("routes", []) if isinstance(route, str)
            }
            missing_routes = sorted(expected_routes - observed_routes)
            unexpected_routes = sorted(observed_routes - expected_routes)
            if missing_routes or unexpected_routes:
                state = "failed"
                add(
                    "error",
                    "route-owner-drift",
                    script,
                    f"Route ownership differs from declaration: {len(missing_routes)} missing, {len(unexpected_routes)} unexpected.",
                )

            if actual.get("bindings_state") != "observed":
                if state == "healthy":
                    state = "unavailable"
                add("warning", "observed-state-unavailable", script, "Worker binding settings were unavailable; binding health is unknown.")
            else:
                expected_bindings = _expected_bindings(expected)
                actual_bindings = _observed_bindings(actual)
                for kind, name, target in sorted(expected_bindings - actual_bindings):
                    state = "failed"
                    finding_type = "missing-service-binding" if kind == "service" else "missing-storage"
                    add("error", finding_type, script, f"Expected {kind} binding {name} to {target} was not observed.")
                for kind, name, target in sorted(actual_bindings - expected_bindings):
                    if state == "healthy":
                        state = "warning"
                    finding_type = "unexpected-service-binding" if kind == "service" else "orphaned-storage"
                    add("warning", finding_type, script, f"Unexpected {kind} binding {name} to {target} was observed on a declared public Worker.")

            metadata = actual.get("metadata")
            if not isinstance(metadata, dict) or metadata.get("state") != "observed":
                if state == "healthy":
                    state = "unavailable"
                add("warning", "observed-state-unavailable", script, "Declared public metadata endpoint was unavailable.")
            elif metadata.get("name") != expected.get("service_id"):
                state = "failed"
                add(
                    "error",
                    "metadata-identity-mismatch",
                    script,
                    f"Metadata identified {metadata.get('name')!r}; expected {expected.get('service_id')!r}.",
                )

        worker_results.append(
            {
                "script_name": script,
                "service_id": expected["service_id"],
                "state": state,
                "metadata": actual.get("metadata", {"state": "unavailable"}),
            }
        )

    declared_pages = {
        item["project_name"]
        for item in declared.get("pages_projects", [])
        if isinstance(item, dict) and isinstance(item.get("project_name"), str)
    }
    observed_pages = {
        item["project_name"]: item.get("observed") is True
        for item in observed.get("pages_projects", [])
        if isinstance(item, dict) and isinstance(item.get("project_name"), str)
    }
    if set(observed_pages) != declared_pages:
        raise TopologyAuditError("observed document must contain exactly the declared public Pages identities")
    page_results = []
    for name in sorted(declared_pages):
        present = observed_pages[name]
        state = "healthy" if present else "failed"
        if not present:
            add("error", "declared-but-not-observed", name, "Declared public Pages project was not observed in Cloudflare.")
        page_results.append({"project_name": name, "state": state})

    aggregates = observed.get("aggregate_counts")
    if not isinstance(aggregates, dict):
        raise TopologyAuditError("observed topology aggregate_counts is missing")
    undeclared_total = sum(
        int(aggregates.get(key, 0) or 0)
        for key in ("workers_undeclared", "routes_undeclared_or_private", "pages_undeclared")
    )
    if undeclared_total:
        add(
            "info",
            "observed-but-undeclared",
            "redacted-provider-topology",
            f"Observed {undeclared_total} undeclared or private topology objects; identities are redacted.",
        )

    hard_failures = sum(finding["severity"] == "error" for finding in findings)
    unavailable = sum(result["state"] == "unavailable" for result in worker_results)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "failed" if hard_failures else ("unavailable" if unavailable else "healthy"),
        "observed_at": observed.get("observed_at"),
        "privacy": {
            "model": "declared-public-identities-plus-aggregate-undeclared-counts",
            "undeclared_identities_redacted": True,
        },
        "summary": {
            "declared_workers": len(worker_results),
            "declared_pages_projects": len(page_results),
            "error_findings": hard_failures,
            "warning_findings": sum(finding["severity"] == "warning" for finding in findings),
            "informational_findings": sum(finding["severity"] == "info" for finding in findings),
            "redacted_undeclared_observations": undeclared_total,
        },
        "workers": worker_results,
        "pages_projects": page_results,
        "findings": findings,
    }


def render(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Atlas public Cloudflare topology audit",
        "",
        f"Status: **{report['status'].upper()}**  ",
        f"Declared Workers: **{summary['declared_workers']}**  ",
        f"Declared Pages projects: **{summary['declared_pages_projects']}**  ",
        f"Error findings: **{summary['error_findings']}**  ",
        f"Warning findings: **{summary['warning_findings']}**  ",
        f"Redacted undeclared observations: **{summary['redacted_undeclared_observations']}**",
        "",
        "> Undeclared provider topology may be private. Its identities are intentionally omitted.",
        "",
        "## Declared public Workers",
        "",
        "| Worker | Service | State |",
        "|---|---|---|",
    ]
    for worker in report["workers"]:
        lines.append(f"| `{worker['script_name']}` | `{worker['service_id']}` | **{worker['state']}** |")
    lines.extend(["", "## Declared Pages projects", "", "| Project | State |", "|---|---|"])
    for project in report["pages_projects"]:
        lines.append(f"| `{project['project_name']}` | **{project['state']}** |")
    if report["findings"]:
        lines.extend(["", "## Findings", ""])
        for finding in report["findings"]:
            lines.append(
                f"- **{finding['severity']} / {finding['type']}** `{finding['subject']}`: {finding['summary']}"
            )
    else:
        lines.extend(["", "No topology findings."])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reconcile declared public Cloudflare topology against a privacy-safe observation.")
    parser.add_argument("--declared", required=True)
    parser.add_argument("--observed", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--markdown-out")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        report = reconcile(load(args.declared), load(args.observed))
    except (OSError, json.JSONDecodeError, TopologyAuditError) as error:
        print(f"topology audit failed closed: {error}", file=sys.stderr)
        return 2
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_out:
        Path(args.markdown_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown_out).write_text(render(report), encoding="utf-8")
    if not args.json_out and not args.markdown_out:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
