from __future__ import annotations

import unittest
from unittest.mock import patch

from atlas_resource_audit.cloudflare_collect import (
    CloudflareAPIError,
    CloudflareError,
    as_resource,
    collect_observed_state,
    paged_array_results,
    r2_bucket_results,
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

    @patch("atlas_resource_audit.cloudflare_collect.request_json")
    def test_page_based_pagination_uses_total_count(self, request_json) -> None:
        request_json.side_effect = [
            {
                "success": True,
                "result": [{"id": "one"}, {"id": "two"}],
                "result_info": {"page": 1, "per_page": 2, "total_count": 3},
            },
            {
                "success": True,
                "result": [{"id": "three"}],
                "result_info": {"page": 2, "per_page": 2, "total_count": 3},
            },
        ]
        results = paged_array_results("/fixture", "token", per_page=2)
        self.assertEqual([{"id": "one"}, {"id": "two"}, {"id": "three"}], results)
        self.assertEqual(2, request_json.call_count)

    @patch("atlas_resource_audit.cloudflare_collect.request_json")
    def test_r2_cursor_pagination_reads_bucket_object(self, request_json) -> None:
        request_json.side_effect = [
            {
                "success": True,
                "result": {"buckets": [{"name": "bucket-a"}]},
                "result_info": {"cursor": "next-page"},
            },
            {
                "success": True,
                "result": {"buckets": [{"name": "bucket-b"}]},
                "result_info": {},
            },
        ]
        results = r2_bucket_results("/fixture", "token")
        self.assertEqual([{"name": "bucket-a"}, {"name": "bucket-b"}], results)
        self.assertEqual("next-page", request_json.call_args_list[1].args[2]["cursor"])

    @patch("atlas_resource_audit.cloudflare_collect.r2_bucket_results")
    @patch("atlas_resource_audit.cloudflare_collect.paged_array_results")
    @patch(
        "atlas_resource_audit.cloudflare_collect.utc_now",
        return_value="2026-07-21T12:00:00Z",
    )
    def test_collect_observed_state_is_sorted_and_minimal(
        self, _utc_now, paged_array_results_mock, r2_bucket_results_mock
    ) -> None:
        paged_array_results_mock.side_effect = [
            [
                {"id": "kv-b", "title": "private-b"},
                {"id": "kv-a", "title": "private-a"},
            ],
            [{"uuid": "d1-a", "name": "private-d1"}],
        ]
        r2_bucket_results_mock.return_value = [
            {"name": "bucket-a", "creation_date": "private-metadata"}
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

    @patch("atlas_resource_audit.cloudflare_collect.r2_bucket_results")
    @patch("atlas_resource_audit.cloudflare_collect.paged_array_results")
    def test_disabled_r2_is_empty_when_no_r2_bucket_is_declared(
        self, paged_array_results_mock, r2_bucket_results_mock
    ) -> None:
        paged_array_results_mock.side_effect = [[], []]
        r2_bucket_results_mock.side_effect = CloudflareAPIError(
            "/accounts/account/r2/buckets",
            [{"code": 10042, "message": "Please enable R2 through the Cloudflare Dashboard."}],
            http_status=403,
        )

        document = collect_observed_state(
            "account",
            "token",
            declared_kinds={"kv-namespace"},
        )

        self.assertEqual([], document["resources"])

    @patch("atlas_resource_audit.cloudflare_collect.r2_bucket_results")
    @patch("atlas_resource_audit.cloudflare_collect.paged_array_results")
    def test_disabled_r2_fails_when_r2_bucket_is_declared(
        self, paged_array_results_mock, r2_bucket_results_mock
    ) -> None:
        paged_array_results_mock.side_effect = [[], []]
        r2_bucket_results_mock.side_effect = CloudflareAPIError(
            "/accounts/account/r2/buckets",
            [{"code": 10042, "message": "Please enable R2 through the Cloudflare Dashboard."}],
            http_status=403,
        )

        with self.assertRaises(CloudflareAPIError):
            collect_observed_state(
                "account",
                "token",
                declared_kinds={"r2-bucket"},
            )

    @patch("atlas_resource_audit.cloudflare_collect.r2_bucket_results")
    @patch("atlas_resource_audit.cloudflare_collect.paged_array_results")
    def test_disabled_r2_fails_without_declaration_context(
        self, paged_array_results_mock, r2_bucket_results_mock
    ) -> None:
        paged_array_results_mock.side_effect = [[], []]
        r2_bucket_results_mock.side_effect = CloudflareAPIError(
            "/accounts/account/r2/buckets",
            [{"code": 10042, "message": "Please enable R2 through the Cloudflare Dashboard."}],
            http_status=403,
        )

        with self.assertRaises(CloudflareAPIError):
            collect_observed_state("account", "token")


if __name__ == "__main__":
    unittest.main()
