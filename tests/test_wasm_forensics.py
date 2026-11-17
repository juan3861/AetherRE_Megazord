"""Tests for GEAR-18: Pure-Python WebAssembly (WASM) Binary & Capability Forensics."""

from __future__ import annotations

from pathlib import Path

from aether_re.wasm_forensics import WASM_MAGIC, WASM_VERSION_1, analyze_wasm_bytes, scan_file_wasm


def _uleb(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
        out.append(b)
        if val == 0:
            break
    return bytes(out)


def _wstr(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(sec_id: int, payload: bytes) -> bytes:
    return bytes([sec_id]) + _uleb(len(payload)) + payload


def _build_synthetic_wasm() -> bytes:
    # Import section (id=2): 2 imports from wasi_snapshot_preview1
    imp1 = _wstr("wasi_snapshot_preview1") + _wstr("fd_write") + bytes([0]) + _uleb(0)
    imp2 = _wstr("wasi_snapshot_preview1") + _wstr("path_open") + bytes([0]) + _uleb(1)
    imp_sec = _section(2, _uleb(2) + imp1 + imp2)

    # Function section (id=3): 1 internal function
    func_sec = _section(3, _uleb(1) + _uleb(0))

    # Export section (id=7): _start (func 2) and memory (mem 0)
    exp1 = _wstr("_start") + bytes([0]) + _uleb(2)
    exp2 = _wstr("memory") + bytes([2]) + _uleb(0)
    exp_sec = _section(7, _uleb(2) + exp1 + exp2)

    # Code section (id=10): 1 body (nop, end)
    code_sec = _section(10, _uleb(1) + bytes([3, 0, 0x01, 0x0B]))

    # Data section (id=11): embedded string
    data_sec = _section(11, b"\x01\x00\x41\x00\x0B\x15AetherWasmPayload2026")

    # Custom section (id=0): producers
    custom_sec = _section(0, _wstr("producers") + b"\x00")

    return WASM_MAGIC + WASM_VERSION_1 + imp_sec + func_sec + exp_sec + code_sec + data_sec + custom_sec


def test_wasm_sections_imports_exports_and_wasi_capabilities(tmp_path: Path):
    wasm_bytes = _build_synthetic_wasm()
    wpath = tmp_path / "module.wasm"
    wpath.write_bytes(wasm_bytes)

    report = scan_file_wasm(wpath)
    assert report.is_wasm is True
    assert report.version == 1
    assert report.runtime_hint == "wasi"
    assert "fd_write" in report.wasi_capabilities
    assert "path_open" in report.wasi_capabilities
    assert report.internal_function_count == 1
    assert any(e["name"] == "_start" and e["kind"] == "func" for e in report.exports)
    assert any("AetherWasmPayload2026" in s for s in report.data_strings)
    assert "producers" in report.custom_sections


def test_wasm_rejects_non_wasm():
    rep = analyze_wasm_bytes(b"NOT_A_WASM_BINARY", "bad.wasm")
    assert rep.is_wasm is False
    assert rep.error is not None
