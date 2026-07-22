from __future__ import annotations

import unittest
from unittest.mock import call, patch

from atlas_resource_audit.topology_collect import _paged_projects


class PagesPaginationTests(unittest.TestCase):
    @patch("atlas_resource_audit.topology_collect.request_json")
    def test_projects_follow_provider_pagination_metadata(self, request_json) -> None:
        path = "/accounts/account/pages/projects"
        request_json.side_effect = [
            {
                "success": True,
                "result": [{"name": "atlas-systems"}],
                "result_info": {
                    "page": 1,
                    "per_page": 20,
                    "total_count": 2,
                    "total_pages": 2,
                },
            },
            {
                "success": True,
                "result": [{"name": "status"}],
                "result_info": {
                    "page": 2,
                    "per_page": 20,
                    "total_count": 2,
                    "total_pages": 2,
                },
            },
        ]

        projects = _paged_projects(path, "token")

        self.assertEqual(
            [{"name": "atlas-systems"}, {"name": "status"}],
            projects,
        )
        self.assertEqual(
            [
                call(path, "token", {"page": "1"}),
                call(path, "token", {"page": "2"}),
            ],
            request_json.call_args_list,
        )

    @patch("atlas_resource_audit.topology_collect.request_json")
    def test_projects_follow_total_count_when_total_pages_is_absent(
        self,
        request_json,
    ) -> None:
        path = "/accounts/account/pages/projects"
        request_json.side_effect = [
            {
                "success": True,
                "result": [{"name": "atlas-systems"}],
                "result_info": {
                    "page": 1,
                    "per_page": 1,
                    "total_count": 2,
                },
            },
            {
                "success": True,
                "result": [{"name": "status"}],
                "result_info": {
                    "page": 2,
                    "per_page": 1,
                    "total_count": 2,
                },
            },
        ]

        projects = _paged_projects(path, "token")

        self.assertEqual(2, len(projects))
        self.assertEqual(2, request_json.call_count)

    @patch("atlas_resource_audit.topology_collect.request_json")
    def test_invalid_total_pages_fails_closed(self, request_json) -> None:
        request_json.return_value = {
            "success": True,
            "result": [],
            "result_info": {"total_pages": 0},
        }

        with self.assertRaisesRegex(ValueError, "total_pages"):
            _paged_projects("/accounts/account/pages/projects", "token")


if __name__ == "__main__":
    unittest.main()
