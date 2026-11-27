"""Pilar 15 (v20.0): Offline Workbench UI, MCP Tools & Field-Reality Benchmark."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from aether_re.mcp_server import AetherMcpDispatcher, TOOLS
from aether_re.workbench_ui import generate_workbench_html

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_workbench_html_generation_and_xss_safety(tmp_path: Path) -> None:
    out = tmp_path / "wb.html"
    rep = generate_workbench_html(
        {
            "custody": {"sha512": "abc123"},
            "decompiler": {"c": "int main() { return 0; }"},
            "timeline": [{"timestamp_utc": "2026-11-25T00:00:00Z", "source": "EVTX", "mitre_tactic": "Execution", "mitre_technique": "T1059", "description": "</script><img src=x>"}],
        },
        out,
    )
    assert rep["panels"] == 6
    html_txt = out.read_text(encoding="utf-8")
    assert "OFFLINE ZERO-CDN" in html_txt
    assert "<\\/script>" in html_txt
    assert "aether-workbench-data" in html_txt


def test_v20_mcp_tools_registered_and_dispatchable(tmp_path: Path) -> None:
    names = {t["name"] for t in TOOLS}
    for req in ("aether_evtx_binxml", "aether_cli_parity_certify", "aether_vm_cfg_devirtualize", "aether_workbench_export"):
        assert req in names

    wb_path = tmp_path / "mcp_wb.html"
    res = AetherMcpDispatcher.handle_workbench_export({"custody": {"ok": True}}, str(wb_path))
    assert res["panels"] == 6 and wb_path.is_file()


def test_benchmark_v20_field_reality_runs_clean() -> None:
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "benchmark_v20_field_reality.py")],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["tls13_rfc8446_live"]["verified"] is True
    assert data["vm_cfg_loops"] >= 1
