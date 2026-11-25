"""Demo: vet every seeded bundle and print one line per decision.

Run:  python3 demo.py     (exit code 0)
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp_skill_gate.cli import main

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    raise SystemExit(main([
        "demo",
        "--bundles", os.path.join(here, "data", "bundles"),
        "--registry", os.path.join(here, "data", "registry.json"),
    ]))
