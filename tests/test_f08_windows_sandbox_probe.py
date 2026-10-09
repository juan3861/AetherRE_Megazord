from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

from tools.f08_windows_sandbox_probe import wait_for_guest_result


def test_wait_for_guest_result_outlives_completed_launcher(tmp_path: Path) -> None:
    """WindowsSandbox.exe may exit before its guest writes mapped evidence."""
    result_file = tmp_path / "guest_result.json"
    launcher = subprocess.Popen([sys.executable, "-c", "pass"])
    launcher.wait(timeout=5)
    assert launcher.poll() == 0

    def write_guest_result() -> None:
        time.sleep(0.1)
        result_file.write_text("marker=guest-complete\n", encoding="utf-8")

    writer = threading.Thread(target=write_guest_result)
    writer.start()
    try:
        assert wait_for_guest_result(
            result_file,
            timeout=2,
            launcher=launcher,
            poll_interval=0.01,
        )
    finally:
        writer.join(timeout=2)

