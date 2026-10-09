from pathlib import Path

from aether_re.process import terminate_processes_under


def test_process_cleanup_missing_root_is_safe(tmp_path: Path):
    assert terminate_processes_under(tmp_path / "does-not-exist") == 0
