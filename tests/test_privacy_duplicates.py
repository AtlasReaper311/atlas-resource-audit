from __future__ import annotations

import json
import unittest

from atlas_resource_audit.__main__ import audit, render


class DuplicatePrivacyTests(unittest.TestCase):
    def test_duplicate_undeclared_identity_is_redacted(self) -> None:
        declared = {
            "schema_version": "atlas-public-cloudflare-resources/v1",
            "owner": "AtlasReaper311/atlas-infra",
            "reviewed_at": "2026-07-21T00:00:00Z",
            "account_id": "fixture-account",
            "privacy_model": "declared-public-resources-only; undeclared provider resources are aggregate-only",
            "resources": [],
        }
        observed = {
            "schema_version": "atlas-resource-audit/observed-cloudflare/v2",
            "provider": "cloudflare",
            "account_id": "fixture-account",
            "observed_at": "2026-07-21T12:00:00Z",
            "resources": [
                {"kind": "kv-namespace", "provider_id": "private-duplicate-id"},
                {"kind": "kv-namespace", "provider_id": "private-duplicate-id"},
            ],
        }

        report = audit(declared, observed)
        self.assertEqual("failed", report["status"])
        serialized = json.dumps(report, sort_keys=True)
        markdown = render(report)
        self.assertNotIn("private-duplicate-id", serialized)
        self.assertNotIn("private-duplicate-id", markdown)
        self.assertEqual(
            {"kind": "kv-namespace", "publicly_declared": False},
            report["findings"][0]["resource"],
        )


if __name__ == "__main__":
    unittest.main()
