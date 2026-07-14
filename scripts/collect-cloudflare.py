#!/usr/bin/env python3
"""CLI wrapper for the Cloudflare observed-state collector."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from atlas_resource_audit.cloudflare_collect import main
raise SystemExit(main())
