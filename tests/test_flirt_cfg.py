"""Unit and ground-truth tests for Pillar 2: CFG Graph-Based FLIRT CRT Recognition."""

from __future__ import annotations

from pathlib import Path

import pefile

from aether_re.flirt_cfg import discover_crt_via_cfg_flirt


def test_discover_crt_via_cfg_flirt_on_real_binaries() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    targets = [
        repo_root / "external_test_repos" / "cjson" / "cjson.dll",
        repo_root / "external_test_repos" / "lz4" / "lz4.dll",
    ]
    for bin_path in targets:
        if not bin_path.is_file():
            continue
        data = bin_path.read_bytes()
        pe = pefile.PE(data=data, fast_load=True)
        res = discover_crt_via_cfg_flirt(pe, data)
        assert res["functions_scanned"] > 100
        matches = res["matches"]
        assert len(matches) >= 6
        found_crt = {m["crt_name"] for m in matches}
        found_strategies = {m["strategy"] for m in matches}
        assert {"noop", "abort", "memcpy", "memset", "strlen"}.issubset(found_crt)
        assert any("security_check_cookie" in s for s in found_strategies)
        assert any("chkstk" in s for s in found_strategies)
        for m in matches:
            assert m["blocks"] >= 1
            assert len(m["skeleton_sha256"]) == 16
