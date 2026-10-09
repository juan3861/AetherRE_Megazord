"""Run project tests without ambient pytest plugins contaminating the replay."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aether_re.test_runner import isolated_pytest_environment


def main() -> int:
    completed = subprocess.run([sys.executable, "-m", "pytest", *sys.argv[1:]], cwd=ROOT, env=isolated_pytest_environment(), check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
