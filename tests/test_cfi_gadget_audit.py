"""Tests for GEAR-19: Control-Flow Integrity (CFI), Intel CET & Gadget Surface Auditor."""

from __future__ import annotations

from pathlib import Path

from aether_re.cfi_gadget_audit import ENDBR64_BYTES, audit_cfi_and_gadgets_bytes, scan_file_cfi_audit


def test_cet_endbr64_and_gadget_surface_detection(tmp_path: Path):
    # Machine code x86_64:
    # f3 0f 1e fa    endbr64
    # ff d0          call rax
    # ff e1          jmp rcx
    # 5f c3          pop rdi ; ret
    # 94 c3          xchg eax, esp ; ret
    # 0f 05 c3       syscall ; ret
    code = (
        ENDBR64_BYTES
        + b"\xff\xd0"
        + b"\xff\xe1"
        + b"\x5f\xc3"
        + b"\x94\xc3"
        + b"\x0f\x05\xc3"
    )
    bin_path = tmp_path / "sample_cet.bin"
    bin_path.write_bytes(code)

    report = scan_file_cfi_audit(bin_path)
    assert report.cet_ibt_enabled is True
    assert report.endbr64_count == 1
    assert report.indirect_call_count >= 1
    assert report.indirect_jmp_count >= 1
    assert report.total_ret_sites == 3
    assert report.unique_gadgets_count >= 3
    assert report.gadget_categories.get("register_pop", 0) >= 1
    assert report.gadget_categories.get("stack_pivot", 0) >= 1
    assert report.gadget_categories.get("syscall_ret", 0) >= 1


def test_empty_buffer_handled_cleanly():
    rep = audit_cfi_and_gadgets_bytes(b"", "empty.bin")
    assert rep.error is not None
