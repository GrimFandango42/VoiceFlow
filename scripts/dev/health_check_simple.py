#!/usr/bin/env python3
"""
Compatibility wrapper for historical simple health-check command paths.

The maintained health check implementation lives in:
    scripts/dev/quick_smoke_test.py
"""

from __future__ import annotations

import runpy
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    print("[INFO] 'health_check_simple.py' is deprecated. Running quick_smoke_test instead.")
    runpy.run_path(str(root / "scripts" / "dev" / "quick_smoke_test.py"), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
