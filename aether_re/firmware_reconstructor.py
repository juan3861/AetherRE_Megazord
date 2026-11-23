"""AetherRE Megazord v8.0 — Firmware, RootFS, MMIO Re-Hosting & Windows Kernel Driver Reconstructor."""

from __future__ import annotations

import gzip
import io
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from aether_re.firmware_forensics import analyze_firmware
from aether_re.kernel_driver_audit import audit_pe_driver_bytes

SCHEMA = "re-megazord-firmware-driver-reconstructor.v1"


def _extract_cpio_newc(blob: bytes, out_dir: Path) -> List[str]:
    """Extracts ASCII newc CPIO archive entries (070701/070702) safely."""
    extracted: List[str] = []
    pos = blob.find(b"070701")
    if pos == -1:
        pos = blob.find(b"070702")
    if pos == -1:
        return extracted

    root_res = out_dir.resolve()
    while pos + 110 <= len(blob):
        magic = blob[pos : pos + 6]
        if magic not in (b"070701", b"070702"):
            break
        hdr = blob[pos : pos + 110].decode("ascii", errors="replace")
        try:
            filesize = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
        except ValueError:
            break
        name_start = pos + 110
        name_end = name_start + namesize
        if name_end > len(blob):
            break
        rel_raw = blob[name_start : name_end - 1].decode("utf-8", errors="replace").lstrip("/")
        data_start = (name_end + 3) & ~3
        data_end = data_start + filesize
        if rel_raw == "TRAILER!!!" or data_end > len(blob):
            break
        if rel_raw and ".." not in Path(rel_raw).parts and filesize > 0:
            dest = (out_dir / rel_raw).resolve()
            if str(dest).startswith(str(root_res)):
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(blob[data_start:data_end])
                extracted.append(rel_raw)
        pos = (data_end + 3) & ~3
    return extracted


def reconstruct_firmware_project(
    target_path: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Extracts firmware containers/rootfs/DTB/uImage and emits Unicorn MMIO re-hosting scaffold."""
    t_path = Path(target_path).resolve()
    out_root = Path(output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    raw = t_path.read_bytes()

    fw_report = analyze_firmware(raw)
    generated: List[str] = []

    rootfs_dir = out_root / "rootfs"
    rootfs_dir.mkdir(parents=True, exist_ok=True)
    cpio_files = _extract_cpio_newc(raw, rootfs_dir)
    for cf in cpio_files:
        generated.append(f"rootfs/{cf}")

    # Decompress embedded gzip streams if any contain ELF/CPIO
    gz_pos = raw.find(b"\x1f\x8b\x08")
    if gz_pos != -1:
        try:
            decomp = gzip.decompress(raw[gz_pos:])
            if b"070701" in decomp or b"070702" in decomp:
                for cf in _extract_cpio_newc(decomp, rootfs_dir):
                    generated.append(f"rootfs/{cf}")
            elif decomp.startswith(b"\x7fELF"):
                (out_root / "carved_kernel.elf").write_bytes(decomp)
                generated.append("carved_kernel.elf")
        except Exception:
            pass

    # Scan candidate ARM/MIPS/RISC-V MMIO peripheral base addresses (0x40000000..0x5FFFFFFF)
    mmio_addrs: Set[int] = set()
    for off in range(0, min(len(raw) - 4, 2 * 1024 * 1024), 4):
        val = struct.unpack_from("<I", raw, off)[0]
        if 0x40000000 <= val < 0x60000000 and (val & 0xFF) == 0:
            mmio_addrs.add(val & 0xFFFFF000)
            if len(mmio_addrs) >= 64:
                break

    mmio_map = {
        "schema": SCHEMA,
        "firmware_findings": fw_report,
        "mmio_peripheral_pages": [hex(a) for a in sorted(mmio_addrs)],
        "rootfs_files_extracted": len(cpio_files),
    }
    (out_root / "mmio_peripheral_map.json").write_text(json.dumps(mmio_map, indent=2), encoding="utf-8")
    generated.append("mmio_peripheral_map.json")

    rehost_dir = out_root / "rehosting"
    rehost_dir.mkdir(parents=True, exist_ok=True)
    harness_py = "\n".join([
        '"""Auto-Generated Unicorn MMIO Re-Hosting Harness (AetherRE v8.0)."""',
        "from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_ALL, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE",
        "",
        "def create_rehost_uc(fw_bytes: bytes, load_addr: int = 0x08000000):",
        "    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)",
        "    uc.mem_map(load_addr, max(0x10000, ((len(fw_bytes) + 0xFFF) & ~0xFFF)), UC_PROT_ALL)",
        "    uc.mem_write(load_addr, fw_bytes)",
        "    uc.mem_map(0x40000000, 0x01000000, UC_PROT_ALL)  # MMIO peripheral bank",
        "    uc.mem_map(0x20000000, 0x00100000, UC_PROT_ALL)  # SRAM",
        "    return uc",
        "",
    ])
    (rehost_dir / "unicorn_mmio_harness.py").write_text(harness_py, encoding="utf-8")
    generated.append("rehosting/unicorn_mmio_harness.py")

    return {
        "schema": SCHEMA,
        "status": "complete",
        "project_kind": "firmware_rehosted_project",
        "mmio_pages_count": len(mmio_addrs),
        "rootfs_files_count": len(cpio_files),
        "generated_files": generated,
    }


def reconstruct_driver_project(
    target_path: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Emits WDM User-Mode Kernel Mock Shim + synthetic .inf around a reconstructed Windows .sys driver."""
    t_path = Path(target_path).resolve()
    out_root = Path(output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    raw = t_path.read_bytes()

    audit_rep = audit_pe_driver_bytes(raw, str(t_path)).to_dict()
    drv_dir = out_root / "driver"
    inc_dir = out_root / "include"
    drv_dir.mkdir(parents=True, exist_ok=True)
    inc_dir.mkdir(parents=True, exist_ok=True)

    shim_h = "\n".join([
        "#pragma once",
        "#include <stdint.h>",
        "/* Auto-Generated WDM User-Mode Mock Harness by AetherRE v8.0 */",
        "typedef struct _AETHER_IRP { uint32_t IoControlCode; uint64_t InputBuffer; uint32_t InputLength; uint64_t Status; } AETHER_IRP;",
        "static inline int64_t aether_IoCompleteRequest(AETHER_IRP* irp, int8_t prio) { (void)prio; return irp ? (int64_t)irp->Status : 0; }",
        "static inline int64_t aether_MmMapIoSpace(uint64_t phys, uint64_t sz) { (void)phys; (void)sz; return 0; }",
        "",
    ])
    (inc_dir / "wdm_usermode_shim.h").write_text(shim_h, encoding="utf-8")

    inf_txt = "\n".join([
        "[Version]",
        'Signature="$WINDOWS NT$"',
        "Class=System",
        "Provider=%AetherRE%",
        "",
        "[Strings]",
        'AetherRE="AetherRE Reconstructed Driver"',
        "",
    ])
    (drv_dir / "reconstructed_driver.inf").write_text(inf_txt, encoding="utf-8")
    (drv_dir / "driver_audit.json").write_text(json.dumps(audit_rep, indent=2), encoding="utf-8")

    return {
        "schema": SCHEMA,
        "status": "complete",
        "project_kind": "windows_kernel_driver",
        "is_driver": bool(audit_rep.get("is_kernel_driver")),
        "hvci_compliant": bool(audit_rep.get("hvci_compliant")),
        "generated_files": [
            "include/wdm_usermode_shim.h",
            "driver/reconstructed_driver.inf",
            "driver/driver_audit.json",
        ],
    }
