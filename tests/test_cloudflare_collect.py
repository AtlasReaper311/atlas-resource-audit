import unittest
from atlas_resource_audit.cloudflare_collect import as_resource

class CloudflareCollectTests(unittest.TestCase):
    def test_as_resource_bounds_metadata(self):
        resource = as_resource("kv-namespace", {
            "id": "abc123", "title": "telemetry-kv",
            "created_on": "2026-07-14T00:00:00Z", "secret": "excluded",
        })
        self.assertEqual(resource["type"], "kv-namespace")
        self.assertEqual(resource["name"], "telemetry-kv")
        self.assertEqual(resource["metadata"], {"created_on": "2026-07-14T00:00:00Z"})

if __name__ == "__main__":
    unittest.main()
