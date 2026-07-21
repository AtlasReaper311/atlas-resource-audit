from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from atlas_resource_audit.topology_collect import _safe_binding, collect_observed_topology
from atlas_resource_audit.topology_reconcile import reconcile, render


class TopologyTests(unittest.TestCase):
    def declared(self) -> dict:
        return {
            "schema_version": "atlas-public-cloudflare-topology/v1",
            "owner": "AtlasReaper311/atlas-infra",
            "account_id": "account",
            "zone_id": "zone",
            "workers": [
                {
                    "script_name": "atlas-api-public",
                    "service_id": "atlas-api-public",
                    "repository": "AtlasReaper311/atlas-api-public",
                    "source_ref": "AtlasReaper311/atlas-api-public:wrangler.toml",
                    "routes": [
                        {"pattern": "api.atlas-systems.uk/v1*", "custom_domain": False}
                    ],
                    "metadata_url": "https://api.atlas-systems.uk/v1/_meta",
                    "service_bindings": [
                        {"binding": "REGISTRY", "service": "atlas-api-index"}
                    ],
                    "storage_bindings": [
                        {
                            "binding": "ATLAS_PUBLIC_KV",
                            "kind": "kv-namespace",
                            "provider_id": "public-kv",
                        }
                    ],
                }
            ],
            "pages_projects": [
                {
                    "project_name": "atlas-systems",
                    "repository": "AtlasReaper311/atlas-systems",
                    "source_ref": "AtlasReaper311/atlas-systems:.github/workflows/deploy.yml",
                    "public_surface": "https://atlas-systems.uk",
                }
            ],
        }

    @patch("atlas_resource_audit.topology_collect._metadata")
    @patch("atlas_resource_audit.topology_collect._settings_bindings")
    @patch("atlas_resource_audit.topology_collect._paged_projects")
    @patch("atlas_resource_audit.topology_collect._array_result")
    @patch("atlas_resource_audit.topology_collect.utc_now", return_value="2026-07-22T00:00:00Z")
    def test_collector_redacts_undeclared_provider_identities(
        self, _now, array_result, paged_projects, settings_bindings, metadata
    ) -> None:
        array_result.side_effect = [
            [{"id": "atlas-api-public"}, {"id": "private-worker-secret"}],
            [
                {"script": "atlas-api-public", "pattern": "api.atlas-systems.uk/v1*"},
                {"script": "private-worker-secret", "pattern": "private.example.invalid/*"},
            ],
        ]
        paged_projects.return_value = [
            {"name": "atlas-systems"},
            {"name": "private-pages-project"},
        ]
        settings_bindings.return_value = (
            "observed",
            [
                {"binding": "REGISTRY", "kind": "service", "target": "atlas-api-index"},
                {"binding": "ATLAS_PUBLIC_KV", "kind": "kv-namespace", "target": "public-kv"},
            ],
        )
        metadata.return_value = {
            "state": "observed",
            "name": "atlas-api-public",
            "version": "1.0.0",
            "status": "live",
        }

        document = collect_observed_topology(self.declared(), "token")
        serialized = json.dumps(document, sort_keys=True)
        self.assertNotIn("private-worker-secret", serialized)
        self.assertNotIn("private.example.invalid", serialized)
        self.assertNotIn("private-pages-project", serialized)
        self.assertEqual(1, document["aggregate_counts"]["workers_undeclared"])
        self.assertEqual(1, document["aggregate_counts"]["routes_undeclared_or_private"])
        self.assertEqual(1, document["aggregate_counts"]["pages_undeclared"])
        self.assertFalse(document["privacy"]["raw_provider_payload_retained"])

    def test_secret_binding_payload_is_never_reduced_to_output(self) -> None:
        self.assertIsNone(
            _safe_binding(
                {
                    "name": "VERY_SECRET",
                    "type": "secret_text",
                    "text": "must-never-leak",
                }
            )
        )

    def observed(self) -> dict:
        return {
            "schema_version": "atlas-resource-audit/observed-topology/v1",
            "provider": "cloudflare",
            "account_id": "account",
            "zone_id": "zone",
            "observed_at": "2026-07-22T00:00:00Z",
            "privacy": {
                "model": "declared-public-identities-plus-aggregate-undeclared-counts",
                "raw_provider_payload_retained": False,
            },
            "aggregate_counts": {
                "workers_total": 1,
                "workers_undeclared": 0,
                "routes_total": 1,
                "routes_undeclared_or_private": 0,
                "pages_total": 1,
                "pages_undeclared": 0,
            },
            "workers": [
                {
                    "script_name": "atlas-api-public",
                    "observed": True,
                    "routes": ["api.atlas-systems.uk/v1*"],
                    "bindings_state": "observed",
                    "bindings": [
                        {"binding": "REGISTRY", "kind": "service", "target": "atlas-api-index"},
                        {"binding": "ATLAS_PUBLIC_KV", "kind": "kv-namespace", "target": "public-kv"},
                    ],
                    "metadata": {
                        "state": "observed",
                        "name": "atlas-api-public",
                        "version": "1.0.0",
                        "status": "live",
                    },
                }
            ],
            "pages_projects": [
                {"project_name": "atlas-systems", "observed": True}
            ],
        }

    def test_healthy_reconciliation(self) -> None:
        report = reconcile(self.declared(), self.observed())
        self.assertEqual("healthy", report["status"])
        self.assertEqual([], report["findings"])

    def test_missing_worker_fails(self) -> None:
        observed = self.observed()
        observed["workers"][0]["observed"] = False
        observed["workers"][0]["routes"] = []
        observed["workers"][0]["bindings_state"] = "not-observed"
        observed["workers"][0]["bindings"] = []
        observed["workers"][0]["metadata"] = {"state": "not-observed"}
        report = reconcile(self.declared(), observed)
        self.assertEqual("failed", report["status"])
        self.assertIn("declared-but-not-observed", {item["type"] for item in report["findings"]})

    def test_missing_service_binding_fails(self) -> None:
        observed = self.observed()
        observed["workers"][0]["bindings"] = [
            {"binding": "ATLAS_PUBLIC_KV", "kind": "kv-namespace", "target": "public-kv"}
        ]
        report = reconcile(self.declared(), observed)
        self.assertIn("missing-service-binding", {item["type"] for item in report["findings"]})

    def test_unexpected_binding_is_warning(self) -> None:
        observed = self.observed()
        observed["workers"][0]["bindings"].append(
            {"binding": "EXTRA", "kind": "service", "target": "atlas-notify"}
        )
        report = reconcile(self.declared(), observed)
        self.assertEqual("warning", report["workers"][0]["state"])
        self.assertIn("unexpected-service-binding", {item["type"] for item in report["findings"]})

    def test_route_drift_fails(self) -> None:
        observed = self.observed()
        observed["workers"][0]["routes"] = ["api.atlas-systems.uk/wrong*"]
        report = reconcile(self.declared(), observed)
        self.assertIn("route-owner-drift", {item["type"] for item in report["findings"]})

    def test_metadata_identity_mismatch_fails(self) -> None:
        observed = self.observed()
        observed["workers"][0]["metadata"]["name"] = "wrong-service"
        report = reconcile(self.declared(), observed)
        self.assertIn("metadata-identity-mismatch", {item["type"] for item in report["findings"]})

    def test_undeclared_provider_observation_stays_aggregate_only(self) -> None:
        observed = self.observed()
        observed["aggregate_counts"]["workers_total"] = 2
        observed["aggregate_counts"]["workers_undeclared"] = 1
        report = reconcile(self.declared(), observed)
        serialized = json.dumps(report, sort_keys=True)
        markdown = render(report)
        self.assertIn("redacted-provider-topology", serialized)
        self.assertNotIn("private-worker", serialized)
        self.assertNotIn("private-worker", markdown)
        self.assertEqual(1, report["summary"]["redacted_undeclared_observations"])


if __name__ == "__main__":
    unittest.main()
