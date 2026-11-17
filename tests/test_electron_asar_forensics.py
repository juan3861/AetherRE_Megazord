"""Tests for GEAR-22: Pure-Python Electron ASAR Archive & V8 Snapshot Security Forensics."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from aether_re.electron_asar_forensics import analyze_asar_bytes, scan_file_asar


def _build_synthetic_asar() -> bytes:
    pkg_bytes = json.dumps(
        {"name": "aether-desktop", "version": "1.0.0", "main": "main.js"}
    ).encode("utf-8")
    main_js = (
        b"const { app, BrowserWindow, shell } = require('electron');\n"
        b"new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n"
        b"shell.openExternal('https://example.com');\n"
    )
    v8_jsc = b"\xde\xc0\xad\xde" + b"\x00" * 32

    payload = pkg_bytes + main_js + v8_jsc
    tree = {
        "files": {
            "package.json": {"size": len(pkg_bytes), "offset": "0"},
            "main.js": {"size": len(main_js), "offset": str(len(pkg_bytes))},
            "app.jsc": {
                "size": len(v8_jsc),
                "offset": str(len(pkg_bytes) + len(main_js)),
            },
        }
    }
    json_bytes = json.dumps(tree).encode("utf-8")
    json_len = len(json_bytes)
    # Pad JSON to 4-byte alignment
    padded_json = json_bytes + b"\x00" * ((4 - (json_len % 4)) % 4)
    str_pickle_size = 4 + len(padded_json)
    hdr_total_size = 4 + str_pickle_size

    header = struct.pack("<IIII", 4, hdr_total_size, str_pickle_size, json_len) + padded_json
    return header + payload


def test_electron_asar_extraction_and_security_audit(tmp_path: Path):
    asar_bytes = _build_synthetic_asar()
    p = tmp_path / "app.asar"
    p.write_bytes(asar_bytes)

    report = scan_file_asar(p)
    assert report.is_asar is True
    assert report.total_files == 3
    assert report.package_json.get("name") == "aether-desktop"
    assert "app.jsc" in report.v8_bytecode_files
    assert "node_integration_enabled" in report.security_risks
    assert "context_isolation_disabled" in report.security_risks
    assert "open_external_sink" in report.security_risks


def test_non_asar_rejected():
    rep = analyze_asar_bytes(b"NOT_AN_ASAR_ARCHIVE", "bad.asar")
    assert rep.is_asar is False
    assert rep.error is not None
