from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from atlas_resource_audit.topology_collect import collect_observed_topology
from atlas_resource_audit.topology_reconcile import reconcile


class CustomDomainTopologyTests(unittest.TestCase):
    def declared(self) -> dict:
        return {
            "schema_version": "atlas-public-cloudflare-topology/v1",
            "owner": "AtlasReaper311/atlas-infra",
            "account_id": "account",
            "zone_id": "zone",
            "workers": [
                {
                    "script_name": "ramone-edge",
                    "service_id": "ramone-edge",
                    "repository": "AtlasReaper311/ramone-edge",
                    "source_ref": "AtlasReaper311/ramone-edge:wrangler.toml",
                    "routes": [
                        {
                            "pattern": "ramone.atlas-systems.uk",
                            "custom_domain": True,
                        },
                        {
                            "pattern": "ramone.atlas-systems.uk/*",
                            "custom_domain": False,
                        },
                    ],
                    "metadata_url": "https://ramone.atlas-systems.uk/_meta",
                    "service_bindings": [],
                    "storage_bindings": [],
                }
            ],
            "pages_projects": [],
        }

    def collect(self, domains: list[dict]) -> dict:
        with (
            patch(
                "atlas_resource_audit.topology_collect._array_result",
                side_effect=[
                    [{"id": "ramone-edge"}],
                    [
                        {
                            "script": "ramone-edge",
                            "pattern": "ramone.atlas-systems.uk/*",
                        }
                    ],
                ],
            ),
            patch(
                "atlas_resource_audit.topology_collect._paged_projects",
                return_value=[],
            ),
            patch(
                "atlas_resource_audit.topology_collect._paged_domains",
                return_value=domains,
            ),
            patch(
                "atlas_resource_audit.topology_collect._settings_bindings",
                return_value=("observed", []),
            ),
            patch(
                "atlas_resource_audit.topology_collect._metadata",
                return_value={
                    "state": "observed",
                    "name": "ramone-edge",
                    "version": "1.0.0",
                    "status": "live",
                },
            ),
            patch(
                "atlas_resource_audit.topology_collect.utc_now",
                return_value="2026-07-22T00:00:00Z",
            ),
        ):
            return collect_observed_topology(self.declared(), "token")

    def test_declared_custom_domain_is_reconciled_with_standard_route(self) -> None:
        observed = self.collect(
            [
                {
                    "hostname": "ramone.atlas-systems.uk",
                    "service": "ramone-edge",
                    "zone_id": "zone",
                }
            ]
        )

        self.assertEqual(
            ["ramone.atlas-systems.uk", "ramone.atlas-systems.uk/*"],
            observed["workers"][0]["routes"],
        )
        report = reconcile(self.declared(), observed)
        self.assertEqual("healthy", report["status"])
        self.assertEqual([], report["findings"])

    def test_missing_custom_domain_fails_route_reconciliation(self) -> None:
        observed = self.collect([])

        report = reconcile(self.declared(), observed)

        self.assertEqual("failed", report["status"])
        self.assertIn(
            "route-owner-drift",
            {finding["type"] for finding in report["findings"]},
        )

    def test_wrong_custom_domain_owner_is_redacted_and_fails(self) -> None:
        observed = self.collect(
            [
                {
                    "hostname": "ramone.atlas-systems.uk",
                    "service": "private-worker-secret",
                    "zone_id": "zone",
                }
            ]
        )
        serialized = json.dumps(observed, sort_keys=True)

        self.assertNotIn("private-worker-secret", serialized)
        self.assertEqual(
            1,
            observed["aggregate_counts"]["routes_undeclared_or_private"],
        )
        report = reconcile(self.declared(), observed)
        self.assertEqual("failed", report["status"])

    def test_undeclared_custom_domain_remains_aggregate_only(self) -> None:
        observed = self.collect(
            [
                {
                    "hostname": "ramone.atlas-systems.uk",
                    "service": "ramone-edge",
                    "zone_id": "zone",
                },
                {
                    "hostname": "private.atlas-systems.uk",
                    "service": "private-worker-secret",
                    "zone_id": "zone",
                },
            ]
        )
        serialized = json.dumps(observed, sort_keys=True)

        self.assertNotIn("private.atlas-systems.uk", serialized)
        self.assertNotIn("private-worker-secret", serialized)
        self.assertEqual(
            1,
            observed["aggregate_counts"]["routes_undeclared_or_private"],
        )
        report = reconcile(self.declared(), observed)
        self.assertEqual("healthy", report["status"])
        self.assertIn(
            "observed-but-undeclared",
            {finding["type"] for finding in report["findings"]},
        )


if __name__ == "__main__":
    unittest.main()
