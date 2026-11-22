"""Unit and ground-truth tests for Win64 .pdata / .xdata UNWIND_INFO & SEH parser (v6.2.0)."""

from __future__ import annotations

from pathlib import Path

import pefile

from aether_re.project_reconstructor import reconstruct_project
from aether_re.win64_unwind import parse_win64_unwind_table


def test_parse_win64_unwind_table_on_real_pe64_binaries(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    targets = [
        repo_root / "external_test_repos" / "cjson" / "cjson.dll",
        repo_root / "external_test_repos" / "cpp_poly" / "poly_test.dll",
        repo_root / "external_test_repos" / "lz4" / "lz4.dll",
    ]
    for bin_path in targets:
        if not bin_path.is_file():
            continue
        data = bin_path.read_bytes()
        pe = pefile.PE(data=data, fast_load=True)
        res = parse_win64_unwind_table(pe, data)
        assert res["total_functions"] > 200
        assert res["ehandlers_count"] >= 50
        records = list(res["records_by_rva"].values())
        assert any(r.stack_frame_bytes > 0 for r in records)
        assert any(len(r.saved_nonvol_regs) > 0 for r in records)
        assert any(r.exception_handler_rva is not None for r in records)

    poly = repo_root / "external_test_repos" / "cpp_poly" / "poly_test.dll"
    if poly.is_file():
        rep = reconstruct_project(poly, tmp_path / "poly_unwind")
        assert rep.architecture == "pe_x86_64"
        assert rep.win64_unwind_functions > 200
        assert rep.win64_ehandlers_count >= 50
