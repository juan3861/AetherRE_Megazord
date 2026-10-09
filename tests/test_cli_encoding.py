import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_cli_help_is_printable_under_legacy_codepage():
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "cp1252"
    result = subprocess.run(
        [sys.executable, "megazord.py", "--help"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0
    assert b"metrics-holdout" in result.stdout
    assert result.stderr == b""
