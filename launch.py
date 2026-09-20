#!/usr/bin/env python3
"""Stable absolute-path launcher. Use -I to isolate from project PYTHONPATH."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from jev_sentinel.cli import main
if __name__ == "__main__":
    raise SystemExit(main())
