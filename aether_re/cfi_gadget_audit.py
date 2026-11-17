"""Control-Flow Integrity (CFI), Intel CET Landing Pads & Gadget Surface Auditor (GEAR-19).

Covers Discovery-100 candidates CAN-058 (cwe_checker), CAN-059 (checksec),
CAN-060 (ROPgadget), and CAN-061 (Ropper) for defensive binary hardening assessment.

Capabilities:
  1. Audits Intel CET Indirect Branch Tracking (IBT) landing pads (endbr64 / endbr32).
  2. Enumerates indirect control-flow transfers (indirect call/jmp via registers or memory).
  3. Quantifies return-oriented / syscall instruction sequences (pop-ret, stack-adjust,
     stack-pivot patterns) to evaluate binary hardening and CET/CFI necessity.
"""

from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import capstone
import pefile

ENDBR64_BYTES = b"\xf3\x0f\x1e\xfa"
ENDBR32_BYTES = b"\xf3\x0f\x1e\xfb"


@dataclass
class GadgetSequence:
    offset: int
    sequence: str
    category: str  # "register_pop", "stack_pivot", "syscall_ret", "arithmetic_ret"


@dataclass
class CfiGadgetAuditReport:
    file_path: str
    architecture: str = "x86_64"
    code_bytes_scanned: int = 0
    endbr64_count: int = 0
    endbr32_count: int = 0
    cet_ibt_enabled: bool = False
    indirect_call_count: int = 0
    indirect_jmp_count: int = 0
    total_ret_sites: int = 0
    unique_gadgets_count: int = 0
    gadget_categories: Dict[str, int] = field(default_factory=dict)
    gadgets_sample: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _extract_executable_blob(data: bytes) -> Tuple[bytes, int, str]:
    """Returns (exec_bytes, base_offset, arch) from PE, ELF, or raw buffer."""
    if len(data) >= 64 and data[:2] == b"MZ":
        try:
            pe = pefile.PE(data=data, fast_load=True)
            arch = "x86" if pe.FILE_HEADER.Machine == 0x014C else "x86_64"
            for sec in pe.sections:
                if sec.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    return sec.get_data()[: 256 * 1024], sec.VirtualAddress, arch
        except Exception:
            pass
    elif len(data) >= 64 and data[:4] == b"\x7fELF":
        arch = "x86" if data[4] == 1 else "x86_64"
        return data[: 256 * 1024], 0, arch

    return data[: 256 * 1024], 0, "x86_64"


def audit_cfi_and_gadgets_bytes(
    data: bytes,
    file_path: str = "",
    force_arch: Optional[str] = None,
) -> CfiGadgetAuditReport:
    """Scans executable code for CET landing pads, indirect branches, and gadget surface."""
    report = CfiGadgetAuditReport(file_path=file_path)
    if not data:
        report.error = "Empty binary buffer."
        return report

    code_blob, base_va, detected_arch = _extract_executable_blob(data)
    arch = force_arch or detected_arch
    report.architecture = arch
    report.code_bytes_scanned = len(code_blob)

    report.endbr64_count = code_blob.count(ENDBR64_BYTES)
    report.endbr32_count = code_blob.count(ENDBR32_BYTES)
    report.cet_ibt_enabled = (report.endbr64_count + report.endbr32_count) > 0

    mode = capstone.CS_MODE_32 if arch == "x86" else capstone.CS_MODE_64
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)

    # 1. Linear disassembly pass for indirect calls/jumps
    for insn in md.disasm(code_blob, base_va):
        mnem = insn.mnemonic
        op = insn.op_str.strip()
        if mnem == "call" and not op.startswith("0x"):
            report.indirect_call_count += 1
        elif mnem == "jmp" and not op.startswith("0x"):
            report.indirect_jmp_count += 1

    # 2. Scan backwards from ret (0xC3) and syscall; ret (0x0F 0x05 0xC3)
    seen_sequences = set()
    ret_positions = [i for i, b in enumerate(code_blob) if b == 0xC3]
    report.total_ret_sites = len(ret_positions)

    for r_idx in ret_positions[:1500]:
        for lookback in range(1, 6):
            start = r_idx - lookback
            if start < 0:
                continue
            window = code_blob[start : r_idx + 1]
            insns = list(md.disasm(window, base_va + start))
            if not insns or insns[-1].mnemonic != "ret":
                continue
            # Ensure instructions cover the entire window cleanly
            consumed = sum(i.size for i in insns)
            if consumed != len(window) or len(insns) < 2:
                continue

            seq_str = " ; ".join(
                f"{i.mnemonic} {i.op_str}".strip() for i in insns
            )
            if seq_str in seen_sequences:
                continue
            seen_sequences.add(seq_str)

            first = insns[0]
            cat = "general_ret"
            if first.mnemonic == "pop":
                cat = "register_pop"
            elif first.mnemonic in ("xchg", "mov", "leave") and any(
                sp in first.op_str for sp in ("rsp", "esp")
            ):
                cat = "stack_pivot"
            elif any(i.mnemonic in ("syscall", "int") for i in insns):
                cat = "syscall_ret"
            elif first.mnemonic in ("add", "sub", "xor"):
                cat = "arithmetic_ret"

            report.gadget_categories[cat] = report.gadget_categories.get(cat, 0) + 1
            if len(report.gadgets_sample) < 60:
                report.gadgets_sample.append(
                    asdict(
                        GadgetSequence(
                            offset=base_va + start,
                            sequence=seq_str,
                            category=cat,
                        )
                    )
                )

    report.unique_gadgets_count = len(seen_sequences)
    return report


def scan_file_cfi_audit(file_path: str | Path) -> CfiGadgetAuditReport:
    """Reads a binary file and executes CFI & gadget surface analysis."""
    p = Path(file_path)
    if not p.is_file():
        return CfiGadgetAuditReport(
            file_path=str(p),
            error=f"File not found: {p}",
        )
    try:
        return audit_cfi_and_gadgets_bytes(p.read_bytes(), str(p))
    except Exception as exc:
        return CfiGadgetAuditReport(
            file_path=str(p),
            error=f"Read error: {exc}",
        )
