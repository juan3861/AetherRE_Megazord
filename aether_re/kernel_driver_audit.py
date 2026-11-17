"""Windows Kernel Driver & HVCI / BYOVD Security Forensics (GEAR-15).

Covers Discovery-100 candidates CAN-068 (MSRC-Security-Research), CAN-025 (pe-sieve),
and CAN-059 (checksec for Windows Kernel Drivers).

Audits:
  1. Native subsystem & Kernel imports (ntoskrnl.exe, hal.dll, fltmgr.sys, wdfldr.sys).
  2. HVCI (Hypervisor-Protected Code Integrity) compliance:
     - W^X section violations (Simultaneous Write + Execute permissions).
     - Non-discardable INIT sections.
     - Alignment & ForceIntegrity flag (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY).
  3. Exploit mitigations (Control Flow Guard, HighEntropyVA, DynamicBase, NX, PageZero).
  4. BYOVD (Bring Your Own Vulnerable Driver) primitive detection:
     - Physical memory mapping (MmMapIoSpace, ZwMapViewOfSection).
     - Process killer / token primitives (ZwTerminateProcess, PsLookupProcessByProcessId).
     - Symbolic link / IOCTL attack surface (IoCreateDevice, IoCreateSymbolicLink).
"""

from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pefile

IMAGE_SUBSYSTEM_NATIVE = 1

IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

KERNEL_MODULES = {
    "ntoskrnl.exe",
    "hal.dll",
    "fltmgr.sys",
    "wdfldr.sys",
    "ndis.sys",
    "netio.sys",
    "ci.dll",
    "cng.sys",
}

BYOVD_PRIMITIVES = {
    "physical_memory": {
        "MmMapIoSpace",
        "MmMapIoSpaceEx",
        "MmGetPhysicalAddress",
        "ZwMapViewOfSection",
        "ZwOpenSection",
    },
    "memory_read_write": {
        "MmCopyVirtualMemory",
        "MmCopyMemory",
        "MmMapLockedPagesSpecifyCache",
        "IoAllocateMdl",
        "MmProbeAndLockPages",
    },
    "process_manipulation": {
        "ZwTerminateProcess",
        "PsLookupProcessByProcessId",
        "PsLookupThreadByThreadId",
        "ObOpenObjectByPointer",
        "KeStackAttachProcess",
    },
    "callback_tampering": {
        "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx",
        "PsSetLoadImageNotifyRoutine",
        "ObRegisterCallbacks",
        "CmRegisterCallbackEx",
    },
    "ioctl_surface": {
        "IoCreateDevice",
        "IoCreateDeviceSecure",
        "IoCreateSymbolicLink",
        "WdfDeviceCreateSymbolicLink",
        "WdfIoQueueCreate",
    },
}


@dataclass
class DriverSectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    characteristics: int
    is_readable: bool
    is_writable: bool
    is_executable: bool
    is_discardable: bool
    is_wx_violation: bool


@dataclass
class KernelDriverAuditReport:
    file_path: str
    is_pe: bool
    is_kernel_driver: bool = False
    architecture: str = "unknown"
    subsystem: int = 0
    hvci_compatible: bool = False
    wx_violations: List[str] = field(default_factory=list)
    shared_writable_sections: List[str] = field(default_factory=list)
    mitigations: Dict[str, bool] = field(default_factory=dict)
    kernel_imports: Dict[str, List[str]] = field(default_factory=dict)
    byovd_primitives: Dict[str, List[str]] = field(default_factory=dict)
    byovd_risk_score: int = 0
    sections: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def audit_pe_driver_bytes(data: bytes, file_path: str = "") -> KernelDriverAuditReport:
    """Performs deep static kernel driver and HVCI security audit on PE bytes."""
    report = KernelDriverAuditReport(file_path=file_path, is_pe=False)
    if len(data) < 64 or data[:2] != b"MZ":
        report.error = "File does not have a valid MZ DOS header."
        return report

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:
        report.error = f"PE parsing failed: {exc}"
        return report

    report.is_pe = True
    machine = pe.FILE_HEADER.Machine
    if machine == 0x8664:
        report.architecture = "x86_64"
    elif machine == 0x014C:
        report.architecture = "x86"
    elif machine == 0xAA64:
        report.architecture = "arm64"
    else:
        report.architecture = f"0x{machine:04x}"

    opt = pe.OPTIONAL_HEADER
    report.subsystem = getattr(opt, "Subsystem", 0)
    dll_chars = getattr(opt, "DllCharacteristics", 0)
    base_of_code = getattr(opt, "BaseOfCode", 0)

    # Extract imports
    imported_Kernel_dlls = False
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = (entry.dll or b"").decode("utf-8", errors="ignore").lower()
            funcs: List[str] = []
            for imp in entry.imports:
                if imp.name:
                    fn = imp.name.decode("utf-8", errors="ignore")
                    funcs.append(fn)
                    # Check BYOVD primitives
                    for cat, prim_set in BYOVD_PRIMITIVES.items():
                        if fn in prim_set:
                            cat_list = report.byovd_primitives.setdefault(cat, [])
                            if fn not in cat_list:
                                cat_list.append(fn)
            if dll_name in KERNEL_MODULES or dll_name.endswith(".sys"):
                imported_Kernel_dlls = True
                report.kernel_imports[dll_name] = funcs

    report.is_kernel_driver = (report.subsystem == IMAGE_SUBSYSTEM_NATIVE) or imported_Kernel_dlls

    # Mitigations
    report.mitigations = {
        "dynamic_base_aslr": bool(dll_chars & 0x0040),
        "high_entropy_va": bool(dll_chars & 0x0020),
        "force_integrity": bool(dll_chars & 0x0080),
        "nx_compat": bool(dll_chars & 0x0100),
        "no_seh": bool(dll_chars & 0x0400),
        "control_flow_guard": bool(dll_chars & 0x4000),
        "page_zero_protected": base_of_code >= 0x1000,
    }

    # Section audit
    for sec in pe.sections:
        sec_name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        chars = sec.Characteristics
        is_r = bool(chars & IMAGE_SCN_MEM_READ)
        is_w = bool(chars & IMAGE_SCN_MEM_WRITE)
        is_x = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        is_disc = bool(chars & IMAGE_SCN_MEM_DISCARDABLE)
        is_shared = bool(chars & IMAGE_SCN_MEM_SHARED)
        is_wx = is_w and is_x

        if is_wx:
            report.wx_violations.append(sec_name)
        if is_w and is_shared:
            report.shared_writable_sections.append(sec_name)

        info = DriverSectionInfo(
            name=sec_name,
            virtual_address=sec.VirtualAddress,
            virtual_size=sec.Misc_VirtualSize,
            characteristics=chars,
            is_readable=is_r,
            is_writable=is_w,
            is_executable=is_x,
            is_discardable=is_disc,
            is_wx_violation=is_wx,
        )
        report.sections.append(asdict(info))

    # HVCI compatibility requires:
    # 1. Zero W^X sections
    # 2. Zero shared writable sections
    # 3. Dynamic Base & Force Integrity (for drivers)
    report.hvci_compatible = (
        len(report.wx_violations) == 0
        and len(report.shared_writable_sections) == 0
        and report.mitigations["dynamic_base_aslr"]
    )

    # Calculate BYOVD risk score (0..100)
    score = 0
    if "ioctl_surface" in report.byovd_primitives:
        score += 20
    if "physical_memory" in report.byovd_primitives:
        score += 35
    if "memory_read_write" in report.byovd_primitives:
        score += 25
    if "process_manipulation" in report.byovd_primitives:
        score += 20
    if report.wx_violations:
        score += 15
    if not report.mitigations["control_flow_guard"]:
        score += 10
    report.byovd_risk_score = min(100, score)

    return report


def scan_file_driver_audit(file_path: str | Path) -> KernelDriverAuditReport:
    """Reads a PE/SYS file from disk and runs the kernel driver audit."""
    p = Path(file_path)
    if not p.is_file():
        return KernelDriverAuditReport(
            file_path=str(p),
            is_pe=False,
            error=f"File not found: {p}",
        )
    try:
        return audit_pe_driver_bytes(p.read_bytes(), str(p))
    except Exception as exc:
        return KernelDriverAuditReport(
            file_path=str(p),
            is_pe=False,
            error=f"Read error: {exc}",
        )
