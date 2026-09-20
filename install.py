#!/usr/bin/env python3
"""Offline installer: inspect by default; write only with --apply."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from jev_sentinel.installer import main
if __name__ == "__main__":
    raise SystemExit(main())
