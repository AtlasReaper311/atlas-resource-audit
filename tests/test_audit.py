from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from atlas_resource_audit.__main__ import (
    ResourceAuditError,
    audit,
    main,
    render,
)


class ResourceAuditTests(unittest.TestCase):
    ACCOUNT_ID = "fixture-account"

    def declared(self) -> dict:
        return {
            "schema_version": "atlas-public-cloudflare-resources/v1",
            "owner": "AtlasReaper311/atlas-infra",
            "reviewed_at": "2026-07-21T00:00:00Z",
            "account_id": self.ACCOUNT_ID,
            "privacy_model": (
                "declared-public-resources-only; undeclared provider resources are aggregate-only"
            ),
            "resources": [
                {
                    "kind": "kv-namespace",
                    "provider_id": "public-kv-001",
                    "display_label": "PUBLIC_CACHE",
                    "owner": {
                        "service_id": "atlas-api-public",
                        "repository": "AtlasReaper311/atlas-api-public",
                        "source_ref": "AtlasReaper311/atlas-api-public:wrangler.toml",
                    },
                    "consumers": [],
                },
                {
                    "kind": "r2-bucket",
                    "provider_id": "public-bucket",
                    "display_label": "PUBLIC_BUCKET",
                    "owner": {
                        "service_id": "atlas-api-public",
                        "repository": "AtlasReaper311/atlas-api-public",
                        "source_ref": "AtlasReaper311/atlas-api-public:wrangler.toml",
                    },
                    "consumers": [],
                },
            ],
        }

    def observed(self) -> dict:
        return {
            "schema_version": "atlas-resource-audit/observed-cloudflare/v2",
            "provider": "cloudflare",
            "account_id": self.ACCOUNT_ID,
            "observed_at": "2026-07-21T12:00:00Z",
            "resources": [
                {"kind": "kv-namespace", "provider_id": "private-kv-secret-id"},
                {"kind": "kv-namespace", "provider_id": "public-kv-001"},
                {"kind": "r2-bucket", "provider_id": "public-bucket"},
            ],
        }

    def test_declared_resources_present_is_healthy(self) -> None:
        report = audit(self.declared(), self.observed())
        self.assertEqual("healthy", report["status"])
        self.assertEqual(2, report["summary"]["declared_present"])
        self.assertEqual(0, report["summary"]["declared_missing"])
        self.assertEqual(1, report["summary"]["undeclared_observed_resources"])
        self.assertEqual(1, report["undeclared_observed_counts"]["kv-namespace"])

    def test_undeclared_provider_identity_is_not_emitted(self) -> None:
        report = audit(self.declared(), self.observed())
        serialized = json.dumps(report, sort_keys=True)
        markdown = render(report)
        self.assertNotIn("private-kv-secret-id", serialized)
        self.assertNotIn("private-kv-secret-id", markdown)
        self.assertIn("aggregate-only", serialized)

    def test_missing_declared_public_resource_fails(self) -> None:
        observed = self.observed()
        observed["resources"] = [
            item
            for item in observed["resources"]
            if item["provider_id"] != "public-bucket"
        ]
        report = audit(self.declared(), observed)
        self.assertEqual("failed", report["status"])
        self.assertEqual(1, report["summary"]["declared_missing"])
        self.assertEqual("missing-public-resource", report["findings"][0]["type"])
        self.assertEqual("PUBLIC_BUCKET", report["findings"][0]["resource"]["display_label"])

    def test_duplicate_observed_provider_identity_fails(self) -> None:
        observed = self.observed()
        observed["resources"].append(
            {"kind": "kv-namespace", "provider_id": "public-kv-001"}
        )
        report = audit(self.declared(), observed)
        self.assertEqual("failed", report["status"])
        self.assertIn(
            "duplicate-provider-identity",
            {finding["type"] for finding in report["findings"]},
        )

    def test_account_mismatch_fails_closed(self) -> None:
        observed = self.observed()
        observed["account_id"] = "different-account"
        with self.assertRaises(ResourceAuditError):
            audit(self.declared(), observed)

    def test_observed_entries_reject_extra_provider_metadata(self) -> None:
        observed = self.observed()
        observed["resources"][0]["name"] = "private-resource-name"
        with self.assertRaises(ResourceAuditError):
            audit(self.declared(), observed)

    def test_declared_identity_must_be_unique(self) -> None:
        declared = self.declared()
        declared["resources"].append(dict(declared["resources"][0]))
        with self.assertRaises(ResourceAuditError):
            audit(declared, self.observed())

    def test_cli_writes_sanitized_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            declared_path = root / "declared.json"
            observed_path = root / "observed.json"
            json_path = root / "report.json"
            markdown_path = root / "report.md"
            declared_path.write_text(
                json.dumps(self.declared(), indent=2) + "\n", encoding="utf-8"
            )
            observed_path.write_text(
                json.dumps(self.observed(), indent=2) + "\n", encoding="utf-8"
            )
            code = main(
                [
                    "--declared",
                    str(declared_path),
                    "--observed",
                    str(observed_path),
                    "--json-out",
                    str(json_path),
                    "--markdown-out",
                    str(markdown_path),
                ]
            )
            self.assertEqual(0, code)
            self.assertNotIn("private-kv-secret-id", json_path.read_text(encoding="utf-8"))
            self.assertNotIn(
                "private-kv-secret-id", markdown_path.read_text(encoding="utf-8")
            )


if __name__ == "__main__":
    unittest.main()
