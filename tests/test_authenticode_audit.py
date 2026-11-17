from __future__ import annotations

import os
from pathlib import Path

import pytest

from aether_re.authenticode_audit import audit_pe_authenticode, scan_file_authenticode


def test_real_signed_windows_pe_valid_digest():
    target = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"
    if not target.is_file():
        pytest.skip("kernel32.dll not available")
    res = scan_file_authenticode(target)
    assert res["status"] == "signed_valid_digest"
    assert res["authenticode"]["signed"] is True
    assert res["authenticode"]["digest_match"] is True
    assert res["authenticode"]["digest_algorithm"] in ("sha1", "sha256")
    assert len(res["authenticode"]["certificates"]) >= 1
    assert res["mitigations"]["aslr"] is True
    assert res["mitigations"]["dep_nx"] is True
    assert res["rich_header"]["present"] is True
    assert len(res["rich_header"]["entries"]) >= 1


def test_tampered_signed_pe_detects_digest_mismatch():
    target = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"
    if not target.is_file():
        pytest.skip("kernel32.dll not available")
    raw = bytearray(target.read_bytes())
    # Flip a byte inside the first section (around 0x1000) to simulate binary tampering
    raw[0x1000] ^= 0xFF
    res = audit_pe_authenticode(bytes(raw))
    assert res["status"] == "signed_digest_mismatch"
    assert res["authenticode"]["signed"] is True
    assert res["authenticode"]["digest_match"] is False


def test_unsigned_local_dll_reports_unsigned_and_rich_header():
    dll = Path(r"D:\AetherRE_Megazord\external_test_repos\cpp_poly\poly_test.dll")
    if not dll.is_file():
        pytest.skip("poly_test.dll not present")
    res = scan_file_authenticode(dll)
    assert res["status"] == "unsigned"
    assert res["authenticode"]["signed"] is False
    assert res["rich_header"]["present"] is True


def test_invalid_inputs_fail_closed():
    assert audit_pe_authenticode(b"") ["status"] == "invalid"
    assert audit_pe_authenticode(b"NOT_A_PE_FILE_123456") ["status"] == "invalid"
    assert audit_pe_authenticode("bad_type") ["status"] == "invalid"  # type: ignore[arg-type]


def test_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_authenticode(r"D:\AetherRE_Megazord\does_not_exist_12345.exe")
