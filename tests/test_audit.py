import json,unittest
from pathlib import Path
from atlas_resource_audit.__main__ import audit
class T(unittest.TestCase):
 def test_orphan(self):
  p=Path("tests/fixtures"); x=audit(json.loads((p/"manifest.json").read_text()),json.loads((p/"bindings.json").read_text()),json.loads((p/"observed.json").read_text())); self.assertTrue(any(f["type"] == "orphaned" and f["resource"]["name"] == "old-kv" for f in x["findings"]))
if __name__=="__main__": unittest.main()
