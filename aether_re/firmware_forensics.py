"""AetherRE Megazord — Deep Firmware, UEFI, FDT, U-Boot & Entropy Carving Engine (GEAR-07).

Pure-static, zero-execution firmware analyzer inspired by uefi-firmware-parser, binwalk, and unblob:
- UEFI Firmware Volume (_FVH) & FFS/DXE module inspection via uefi_firmware
- U-Boot uImage header parsing (0x27051956)
- Flattened Device Tree (FDT/DTB) header parsing (0xd00dfeed)
- Filesystem & compressed stream signature carving (SquashFS, CramFS, Gzip, XZ, Zstd, BZip2, ELF, PE)
- Sliding-window Shannon entropy profiling for packed/encrypted region detection
"""

from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any

SCHEMA = "re-megazord-firmware-forensics.v1"
MAX_FIRMWARE_BYTES = 256 * 1024 * 1024

_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"_FVH", "uefi_fv", "UEFI Firmware Volume Header"),
    (b"\xd0\x0d\xfe\xed", "fdt_dtb", "Flattened Device Tree (DTB)"),
    (b"\x27\x05\x19\x56", "uboot_uimage", "U-Boot legacy uImage"),
    (b"hsqs", "squashfs_le", "SquashFS filesystem (little-endian)"),
    (b"sqsh", "squashfs_be", "SquashFS filesystem (big-endian)"),
    (b"\x28\xcd\x3d\x45", "cramfs_le", "CramFS filesystem (little-endian)"),
    (b"\x1f\x8b\x08", "gzip", "Gzip compressed stream"),
    (b"\xfd7zXZ\x00", "xz", "XZ compressed stream"),
    (b"\x28\xb5\x2f\xfd", "zstd", "Zstandard compressed stream"),
    (b"BZh", "bzip2", "BZip2 compressed stream"),
    (b"\x7fELF", "elf", "Embedded ELF binary"),
]


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    n = len(chunk)
    ent = 0.0
    log2_fn = math.log2
    for c in counts:
        if c:
            p = c / n
            ent -= p * log2_fn(p)
    return round(ent, 4)


def _parse_uboot_uimage(blob: bytes, off: int) -> dict[str, Any] | None:
    if off + 64 > len(blob):
        return None
    magic, _, _, size, load_addr, ep_addr, _, os_id, arch_id, img_type, comp_id = struct.unpack_from(
        ">IIIIIIIBBBB", blob, off
    )
    if magic != 0x27051956 or size == 0 or size > len(blob):
        return None
    name = blob[off + 32:off + 64].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return {
        "name": name,
        "data_size": size,
        "load_address": hex(load_addr),
        "entry_point": hex(ep_addr),
        "os_id": os_id,
        "arch_id": arch_id,
        "image_type": img_type,
        "compression_id": comp_id,
    }


def _parse_fdt_header(blob: bytes, off: int) -> dict[str, Any] | None:
    if off + 40 > len(blob):
        return None
    magic, totalsize, off_dt_struct, off_dt_strings, _, version, last_comp_ver = struct.unpack_from(
        ">IIIIIII", blob, off
    )
    if magic != 0xD00DFEED or totalsize < 40 or totalsize > len(blob) - off:
        return None
    return {
        "totalsize": totalsize,
        "version": version,
        "last_comp_version": last_comp_ver,
        "off_dt_struct": off_dt_struct,
        "off_dt_strings": off_dt_strings,
    }


def _inspect_uefi(blob: bytes) -> dict[str, Any]:
    try:
        import uefi_firmware  # type: ignore[import-untyped]
        parser = uefi_firmware.AutoParser(blob)
        ftype = parser.type()
        if ftype == "unknown":
            return {"detected": False, "type": "unknown", "modules": []}
        parsed = parser.parse()
        modules: list[dict[str, Any]] = []

        def _walk(obj: Any, depth: int = 0) -> None:
            if depth > 10 or len(modules) >= 500:
                return
            info = getattr(obj, "guid", None)
            name = getattr(obj, "name", None)
            if info or name:
                modules.append({
                    "type": type(obj).__name__,
                    "guid": str(info) if info else None,
                    "name": str(name) if name else None,
                })
            for attr in ("objects", "sections", "files", "volumes"):
                children = getattr(obj, attr, None)
                if isinstance(children, list):
                    for ch in children:
                        _walk(ch, depth + 1)

        if parsed is not None:
            _walk(parsed)
        return {"detected": True, "type": str(ftype), "modules": modules}
    except Exception as exc:
        return {"detected": False, "error": str(exc), "modules": []}


def analyze_firmware(data: bytes, *, chunk_size: int = 4096) -> dict[str, Any]:
    """Perform static signature carving, U-Boot/FDT/UEFI inspection, and entropy profiling."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_FIRMWARE_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "input_too_large"}
    if not blob:
        return {"schema": SCHEMA, "status": "invalid", "code": "empty_input"}

    carved: list[dict[str, Any]] = []
    for sig, kind, desc in _SIGNATURES:
        pos = 0
        while len(carved) < 500:
            idx = blob.find(sig, pos)
            if idx == -1:
                break
            entry: dict[str, Any] = {"offset": idx, "offset_hex": hex(idx), "kind": kind, "description": desc}
            if kind == "uboot_uimage":
                parsed_ub = _parse_uboot_uimage(blob, idx)
                if parsed_ub is None:
                    pos = idx + 4
                    continue
                entry["metadata"] = parsed_ub
            elif kind == "fdt_dtb":
                parsed_fdt = _parse_fdt_header(blob, idx)
                if parsed_fdt is None:
                    pos = idx + 4
                    continue
                entry["metadata"] = parsed_fdt
            elif kind == "uefi_fv":
                # _FVH is at offset +0x28 inside EFI_FIRMWARE_VOLUME_HEADER
                entry["fv_base_offset"] = max(0, idx - 0x28)
            carved.append(entry)
            pos = idx + max(1, len(sig))

    carved.sort(key=lambda x: x["offset"])

    # Entropy profile (single-pass accumulation for both chunk and global entropy)
    step = max(256, chunk_size)
    high_entropy_regions: list[dict[str, Any]] = []
    entropies: list[float] = []
    global_counts = [0] * 256
    global_bytes = 0
    log2_fn = math.log2
    limit = min(len(blob), 16 * 1024 * 1024)
    for off in range(0, limit, step):
        chunk = blob[off:off + step]
        counts = [0] * 256
        for b in chunk:
            counts[b] += 1
        n = len(chunk)
        ent = 0.0
        if off < 1024 * 1024:
            global_bytes += n
            for idx_b, c in enumerate(counts):
                if c:
                    global_counts[idx_b] += c
                    p = c / n
                    ent -= p * log2_fn(p)
        else:
            for c in counts:
                if c:
                    p = c / n
                    ent -= p * log2_fn(p)
        ent = round(ent, 4)
        entropies.append(ent)
        if ent >= 7.2:
            high_entropy_regions.append({"offset": off, "size": n, "entropy": ent})

    global_ent = 0.0
    if global_bytes > 0:
        for c in global_counts:
            if c:
                p = c / global_bytes
                global_ent -= p * log2_fn(p)
        global_ent = round(global_ent, 4)

    uefi_info = _inspect_uefi(blob) if b"_FVH" in blob else {"detected": False, "modules": []}

    return {
        "schema": SCHEMA,
        "status": "complete",
        "size_bytes": len(blob),
        "global_entropy": global_ent,
        "high_entropy_chunk_count": len(high_entropy_regions),
        "high_entropy_regions": high_entropy_regions[:100],
        "total_signatures": len(carved),
        "signatures": carved,
        "uefi": uefi_info,
    }


def scan_file_firmware(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_FIRMWARE_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    report = analyze_firmware(path.read_bytes())
    report["target"] = str(path)
    return report
