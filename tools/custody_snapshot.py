"""Create a safe, create-only Phase 0 custody snapshot manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow direct execution from a source checkout without requiring installation.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aether_re.custody_release import capture_custody_snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="repository root to inventory")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory where the manifest is created")
    arguments = parser.parse_args()
    report = capture_custody_snapshot(arguments.root, arguments.output_dir)
    print(json.dumps({"schema": report["schema"], "output": report["output"], "file_count": len(report["files"]), "excluded_count": len(report["excluded"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
