"""Windows Kernel Driver IOCTL Dispatcher & IRP Security Audit Engine (v11.0).

Statically disassembles PE kernel drivers (`.sys`) and analyzes IRP_MJ_DEVICE_CONTROL code:
  1. Extracts Windows CTL_CODE IOCTL constants (`DeviceType`, `Function`, `Method`:
     `METHOD_BUFFERED`, `METHOD_IN_DIRECT`, `METHOD_OUT_DIRECT`, `METHOD_NEITHER`) and `Access`.
  2. Flags high-risk `METHOD_NEITHER` raw user-mode pointers (`Type3InputBuffer` / `UserBuffer`),
     missing `ProbeForRead`/`ProbeForWrite`, and `wrmsr`/`out dx, al`/`MmMapIoSpace` BYOVD sinks.
  3. Proves malformed IRP buffer lengths / integer-overflow IOCTL payloads with Z3.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

import capstone
import pefile

from aether_re.exploit_prover import prove_c_allocation_overflow_z3
from aether_re.kernel_driver_audit import audit_pe_driver_bytes

SCHEMA = "re-megazord-driver-ioctl-fuzzer.v1"

_METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}
_ACCESS_NAMES = {0: "FILE_ANY_ACCESS", 1: "FILE_READ_ACCESS", 2: "FILE_WRITE_ACCESS", 3: "FILE_READ_WRITE_ACCESS"}


def decode_ctl_code(ioctl: int) -> Dict[str, Any]:
    device_type = (ioctl >> 16) & 0xFFFF
    access = (ioctl >> 14) & 0x3
    function = (ioctl >> 2) & 0xFFF
    method = ioctl & 0x3
    return {
        "ioctl_hex": hex(ioctl & 0xFFFFFFFF),
        "device_type": hex(device_type),
        "function": hex(function),
        "method": _METHOD_NAMES.get(method, str(method)),
        "method_id": method,
        "access": _ACCESS_NAMES.get(access, str(access)),
    }


def _is_plausible_ctl_code(val: int) -> bool:
    dev = (val >> 16) & 0xFFFF
    fn = (val >> 2) & 0xFFF
    # Typical Windows FILE_DEVICE_UNKNOWN (0x0022), CUSTOM (>= 0x8000), or DISK/TRANSPORT (0x01..0x50)
    return (dev == 0x0022 or dev >= 0x8000 or 0x0001 <= dev <= 0x0050) and (fn >= 0x800 or dev == 0x0022)


def audit_driver_ioctls_and_irps(
    pe_bytes: bytes,
    *,
    driver_c_code: Optional[str] = None,
) -> Dict[str, Any]:
    """Extracts CTL_CODE IOCTLs, WDM/WDF primitives, and proves IRP length/overflow vulnerabilities."""
    base_rep = audit_pe_driver_bytes(pe_bytes).to_dict()
    if len(pe_bytes) < 64 or pe_bytes[:2] != b"MZ":
        return {"schema": SCHEMA, "status": "not_pe", "driver_audit": base_rep, "ioctls": [], "irp_findings": []}

    pe = pefile.PE(data=pe_bytes, fast_load=True)
    is_64 = pe.FILE_HEADER.Machine == 0x8664
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32)

    ioctls_found: Dict[int, Dict[str, Any]] = {}
    privileged_insns: List[Dict[str, Any]] = []
    for sec in getattr(pe, "sections", []):
        if not (sec.Characteristics & 0x20000000):
            continue
        rva_base = int(sec.VirtualAddress)
        raw_off = int(sec.PointerToRawData)
        sz = min(int(sec.Misc_VirtualSize), len(pe_bytes) - raw_off, 256 * 1024)
        code = pe_bytes[raw_off : raw_off + sz]
        for ins in md.disasm(code, rva_base):
            m = ins.mnemonic.lower()
            op = ins.op_str.lower()
            if m in ("cmp", "sub", "mov") and "," in op:
                rhs = op.split(",", 1)[1].strip()
                if rhs.startswith("0x"):
                    try:
                        val = int(rhs, 16)
                        if 0x00010000 <= val <= 0xFFFFFFFF and _is_plausible_ctl_code(val):
                            dec = decode_ctl_code(val)
                            dec["rva"] = hex(ins.address)
                            ioctls_found[val] = dec
                    except ValueError:
                        pass
            if m in ("wrmsr", "rdmsr", "in", "out", "cli", "hlt", "lgdt", "lidt", "invlpg"):
                privileged_insns.append({"rva": hex(ins.address), "insn": f"{m} {op}".strip()})

    irp_findings: List[Dict[str, Any]] = []
    # Check METHOD_NEITHER without ProbeForRead/ProbeForWrite
    imports_flat = {fn for fns in base_rep.get("kernel_imports", {}).values() for fn in fns}
    has_probe = "ProbeForRead" in imports_flat or "ProbeForWrite" in imports_flat
    for dec in ioctls_found.values():
        if dec["method"] == "METHOD_NEITHER" and not has_probe:
            irp_findings.append({
                "rule_id": "AETHER-DRV-NEITHER-NOPROBE",
                "severity": "critical",
                "ioctl": dec["ioctl_hex"],
                "message": f"IOCTL {dec['ioctl_hex']} uses METHOD_NEITHER without ProbeForRead/ProbeForWrite import.",
            })

    if base_rep.get("byovd_primitives"):
        irp_findings.append({
            "rule_id": "AETHER-DRV-BYOVD",
            "severity": "high",
            "primitives": base_rep["byovd_primitives"],
            "message": f"Dangerous BYOVD primitives imported alongside {len(ioctls_found)} IOCTL handlers.",
        })

    if privileged_insns:
        irp_findings.append({
            "rule_id": "AETHER-DRV-PRIV-INSN",
            "severity": "high",
            "count": len(privileged_insns),
            "sample": privileged_insns[:10],
            "message": "Direct privileged Ring-0 hardware/MSR/port instruction detected inside driver `.text`.",
        })

    if driver_c_code:
        m_al = re.search(r"\b(?:ExAllocatePool(?:WithTag|2)?|malloc|aether_malloc)\s*\(([^;]+)\)\s*;", driver_c_code)
        if m_al:
            arg_expr = m_al.group(1).rsplit(",", 1)[-1].strip()
            tainted = [v for v in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", arg_expr) if v not in ("int64_t", "uint32_t")]
            if tainted and any(op in arg_expr for op in ("+", "*")):
                poc = prove_c_allocation_overflow_z3(arg_expr, tainted[:3], bitwidth=32)
                if poc.get("vulnerable"):
                    irp_findings.append({
                        "rule_id": "AETHER-DRV-IRP-INT-OVERFLOW",
                        "severity": "critical",
                        "cwe": "CWE-190",
                        "poc": poc,
                        "message": f"Z3-proven IRP Pool Allocation Integer Overflow in `{arg_expr}`",
                    })

    return {
        "schema": SCHEMA,
        "status": "complete",
        "driver_audit": base_rep,
        "ioctls_count": len(ioctls_found),
        "ioctls": list(ioctls_found.values()),
        "privileged_instructions": privileged_insns[:25],
        "irp_findings": irp_findings,
    }
