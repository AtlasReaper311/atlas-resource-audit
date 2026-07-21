from __future__ import annotations

import unittest
from unittest.mock import patch

from atlas_resource_audit.cloudflare_collect import (
    CloudflareError,
    as_resource,
    collect_observed_state,
)


class CloudflareCollectTests(unittest.TestCase):
    def test_as_resource_emits_minimum_identity_only(self) -> None:
        resource = as_resource(
            "kv-namespace",
            {
                "id": "abc123",
                "title": "private-name-must-not-propagate",
                "created_on": "2026-07-14T00:00:00Z",
                "secret": "excluded",
            },
        )
        self.assertEqual(
            {"kind": "kv-namespace", "provider_id": "abc123"}, resource
        )

    def test_bucket_name_is_used_when_provider_has_no_id(self) -> None:
        resource = as_resource("r2-bucket", {"name": "public-bucket"})
        self.assertEqual(
            {"kind": "r2-bucket", "provider_id": "public-bucket"}, resource
        )

    def test_resource_without_identity_fails_closed(self) -> None:
        with self.assertRaises(CloudflareError):
            as_resource("kv-namespace", {"title": "no-stable-id"})

    @patch("atlas_resource_audit.cloudflare_collect.paged_results")
    @patch(
        "atlas_resource_audit.cloudflare_collect.utc_now",
        return_value="2026-07-21T12:00:00Z",
    )
    def test_collect_observed_state_is_sorted_and_minimal(
        self, _utc_now, paged_results
    ) -> None:
        paged_results.side_effect = [
            [
                {"id": "kv-b", "title": "private-b"},
                {"id": "kv-a", "title": "private-a"},
            ],
            [{"uuid": "d1-a", "name": "private-d1"}],
            [{"name": "bucket-a", "creation_date": "private-metadata"}],
        ]
        document = collect_observed_state("account", "token")
        self.assertEqual(
            "atlas-resource-audit/observed-cloudflare/v2",
            document["schema_version"],
        )
        self.assertEqual("cloudflare", document["provider"])
        self.assertEqual("account", document["account_id"])
        self.assertEqual(
            [
                {"kind": "d1-database", "provider_id": "d1-a"},
                {"kind": "kv-namespace", "provider_id": "kv-a"},
                {"kind": "kv-namespace", "provider_id": "kv-b"},
                {"kind": "r2-bucket", "provider_id": "bucket-a"},
            ],
            document["resources"],
        )
        serialized = str(document)
        self.assertNotIn("private-a", serialized)
        self.assertNotIn("private-b", serialized)
        self.assertNotIn("private-d1", serialized)
        self.assertNotIn("private-metadata", serialized)


if __name__ == "__main__":
    unittest.main()
