"""Physical RAM Forensics Analyzer for AetherRE Megazord (v11.5).

Pure-Python deep memory forensics engine supporting:
1. x64 4-level paging (CR3 -> PML4 -> PDPT -> PD -> PT) virtual-to-physical
   translation including 1GB huge pages, 2MB large pages, and NX/RW/User flags.
2. Independent EPROCESS / KPROCESS pool-tag scanning vs ActiveProcessLinks walk
   to detect DKOM hidden processes (`DKOM_HIDDEN_PROCESS`).
3. Executable RWX unbacked page detection, inline kernel/user hook detection
   (`JMP rel32`, `FF 25`, `mov rax; jmp rax`), and in-memory PE carving with
   optional handoff to `reconstruct_project`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import struct
from typing import Any


_PAGE_SIZE = 0x1000
_ADDR_MASK = 0x000FFFFFFFFFF000
_FILETIME_EPOCH_DIFF = 116444736000000000


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def _i32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<i", buf, off)[0]


def _filetime_to_iso(ft: int) -> str | None:
    if ft <= _FILETIME_EPOCH_DIFF or ft > 0x02FFFFFFFFFFFFFF:
        return None
    us = (ft - _FILETIME_EPOCH_DIFF) // 10
    try:
        dt = datetime.fromtimestamp(us / 1_000_000.0, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return None


@dataclass(frozen=True)
class EprocessProfile:
    """Offsets inside Windows x64 EPROCESS (Win10/Win11 defaults)."""

    directory_table_base: int = 0x028
    unique_process_id: int = 0x440
    active_process_links: int = 0x448
    create_time: int = 0x468
    image_file_name: int = 0x5A8
    eprocess_size: int = 0x600


def translate_va_x64_pml4(
    dump_bytes: bytes,
    cr3: int,
    va: int,
    phys_base: int = 0,
) -> dict[str, Any]:
    """Translate an x64 64-bit virtual address using 4-level CR3 PML4 paging."""
    cr3_phys = (cr3 & _ADDR_MASK) - phys_base
    if cr3_phys < 0 or cr3_phys + _PAGE_SIZE > len(dump_bytes):
        return {"mapped": False, "reason": "cr3_out_of_range", "va": hex(va)}

    pml4_idx = (va >> 39) & 0x1FF
    pml4e = _u64(dump_bytes, cr3_phys + pml4_idx * 8)
    if not (pml4e & 0x1):
        return {"mapped": False, "reason": "pml4e_not_present", "va": hex(va)}

    pdpt_phys = (pml4e & _ADDR_MASK) - phys_base
    if pdpt_phys < 0 or pdpt_phys + _PAGE_SIZE > len(dump_bytes):
        return {"mapped": False, "reason": "pdpt_out_of_range", "va": hex(va)}

    pdpt_idx = (va >> 30) & 0x1FF
    pdpte = _u64(dump_bytes, pdpt_phys + pdpt_idx * 8)
    if not (pdpte & 0x1):
        return {"mapped": False, "reason": "pdpte_not_present", "va": hex(va)}

    if pdpte & 0x80:  # 1GB huge page
        phys = (pdpte & 0x000FFFFFC0000000) | (va & 0x3FFFFFFF)
        return _build_translation_result(va, phys, pml4e & pdpte, pdpte, "1GB")

    pd_phys = (pdpte & _ADDR_MASK) - phys_base
    if pd_phys < 0 or pd_phys + _PAGE_SIZE > len(dump_bytes):
        return {"mapped": False, "reason": "pd_out_of_range", "va": hex(va)}

    pd_idx = (va >> 21) & 0x1FF
    pde = _u64(dump_bytes, pd_phys + pd_idx * 8)
    if not (pde & 0x1):
        return {"mapped": False, "reason": "pde_not_present", "va": hex(va)}

    if pde & 0x80:  # 2MB large page
        phys = (pde & 0x000FFFFFFFE00000) | (va & 0x1FFFFF)
        return _build_translation_result(va, phys, pml4e & pdpte & pde, pde, "2MB")

    pt_phys = (pde & _ADDR_MASK) - phys_base
    if pt_phys < 0 or pt_phys + _PAGE_SIZE > len(dump_bytes):
        return {"mapped": False, "reason": "pt_out_of_range", "va": hex(va)}

    pt_idx = (va >> 12) & 0x1FF
    pte = _u64(dump_bytes, pt_phys + pt_idx * 8)
    if not (pte & 0x1):
        return {"mapped": False, "reason": "pte_not_present", "va": hex(va)}

    phys = (pte & _ADDR_MASK) | (va & 0xFFF)
    return _build_translation_result(va, phys, pml4e & pdpte & pde & pte, pte, "4KB")


def _build_translation_result(
    va: int, phys: int, hier_bits: int, leaf_entry: int, page_size: str
) -> dict[str, Any]:
    writable = bool(hier_bits & 0x2)
    user = bool(hier_bits & 0x4)
    nx = bool(leaf_entry >> 63)
    return {
        "mapped": True,
        "va": hex(va),
        "pa": hex(phys),
        "pa_int": phys,
        "page_size": page_size,
        "writable": writable,
        "user": user,
        "executable": not nx,
        "rwx": writable and (not nx),
    }


def walk_pml4_pages(
    dump_bytes: bytes, cr3: int, phys_base: int = 0, max_pages: int = 8192
) -> list[dict[str, Any]]:
    """Enumerate mapped x64 virtual pages under a given CR3."""
    pages: list[dict[str, Any]] = []
    cr3_phys = (cr3 & _ADDR_MASK) - phys_base
    if cr3_phys < 0 or cr3_phys + _PAGE_SIZE > len(dump_bytes):
        return pages

    for i4 in range(512):
        pml4e = _u64(dump_bytes, cr3_phys + i4 * 8)
        if not (pml4e & 0x1):
            continue
        pdpt_phys = (pml4e & _ADDR_MASK) - phys_base
        if pdpt_phys < 0 or pdpt_phys + _PAGE_SIZE > len(dump_bytes):
            continue
        canon_prefix = (0xFFFF << 48) if (i4 >= 256) else 0
        for i3 in range(512):
            pdpte = _u64(dump_bytes, pdpt_phys + i3 * 8)
            if not (pdpte & 0x1):
                continue
            if pdpte & 0x80:
                va = canon_prefix | (i4 << 39) | (i3 << 30)
                pages.append(_build_translation_result(va, pdpte & 0x000FFFFFC0000000, pml4e & pdpte, pdpte, "1GB"))
                if len(pages) >= max_pages:
                    return pages
                continue
            pd_phys = (pdpte & _ADDR_MASK) - phys_base
            if pd_phys < 0 or pd_phys + _PAGE_SIZE > len(dump_bytes):
                continue
            for i2 in range(512):
                pde = _u64(dump_bytes, pd_phys + i2 * 8)
                if not (pde & 0x1):
                    continue
                if pde & 0x80:
                    va = canon_prefix | (i4 << 39) | (i3 << 30) | (i2 << 21)
                    pages.append(_build_translation_result(va, pde & 0x000FFFFFFFE00000, pml4e & pdpte & pde, pde, "2MB"))
                    if len(pages) >= max_pages:
                        return pages
                    continue
                pt_phys = (pde & _ADDR_MASK) - phys_base
                if pt_phys < 0 or pt_phys + _PAGE_SIZE > len(dump_bytes):
                    continue
                for i1 in range(512):
                    pte = _u64(dump_bytes, pt_phys + i1 * 8)
                    if not (pte & 0x1):
                        continue
                    va = canon_prefix | (i4 << 39) | (i3 << 30) | (i2 << 21) | (i1 << 12)
                    pages.append(_build_translation_result(va, pte & _ADDR_MASK, pml4e & pdpte & pde & pte, pte, "4KB"))
                    if len(pages) >= max_pages:
                        return pages
    return pages


def _read_virtual_bytes(
    dump_bytes: bytes, cr3: int, va: int, size: int, phys_base: int = 0
) -> bytes | None:
    tr = translate_va_x64_pml4(dump_bytes, cr3, va, phys_base=phys_base)
    if not tr.get("mapped"):
        return None
    pa = tr["pa_int"] - phys_base
    if pa < 0 or pa + size > len(dump_bytes):
        return None
    return dump_bytes[pa : pa + size]


def _extract_image_name(raw_name: bytes) -> str:
    nul = raw_name.find(b"\x00")
    if nul != -1:
        raw_name = raw_name[:nul]
    if not raw_name:
        return ""
    if all(32 <= b < 127 for b in raw_name):
        return raw_name.decode("ascii", errors="replace")
    return ""


def _scan_pool_eprocesses(
    dump_bytes: bytes, profile: EprocessProfile
) -> list[dict[str, Any]]:
    """Scan physical memory for Windows `Proc` pool tags followed by EPROCESS."""
    found: list[dict[str, Any]] = []
    seen_offsets: set[int] = set()
    idx = 0
    tag = b"Proc"
    while True:
        idx = dump_bytes.find(tag, idx)
        if idx == -1:
            break
        # Pool tag sits at +4 of _POOL_HEADER (16 bytes), optional _OBJECT_HEADER (48..96 bytes)
        # before KPROCESS (`0x03 0x00` dispatcher header). Scan candidate shifts safely.
        for delta in (0x0C, 0x3C, 0x4C, 0x5C, 0x6C, 0x7C, 0x8C, 0x9C):
            ep_off = idx + delta
            if ep_off in seen_offsets or ep_off + profile.eprocess_size > len(dump_bytes):
                continue
            # KPROCESS DispatcherHeader.Type == 0x03 (ProcessObject)
            if dump_bytes[ep_off] != 0x03 or dump_bytes[ep_off + 1] != 0x00:
                continue
            dtb = _u64(dump_bytes, ep_off + profile.directory_table_base)
            pid = _u64(dump_bytes, ep_off + profile.unique_process_id)
            raw_name = dump_bytes[ep_off + profile.image_file_name : ep_off + profile.image_file_name + 15]
            name = _extract_image_name(raw_name)
            if name and (0 <= pid <= 0x1000000) and (dtb & 0xFFF) == 0:
                seen_offsets.add(ep_off)
                ct = _u64(dump_bytes, ep_off + profile.create_time)
                flink = _u64(dump_bytes, ep_off + profile.active_process_links)
                blink = _u64(dump_bytes, ep_off + profile.active_process_links + 8)
                found.append(
                    {
                        "pid": pid,
                        "name": name,
                        "eprocess_pa": ep_off,
                        "dtb": hex(dtb),
                        "create_time_utc": _filetime_to_iso(ct),
                        "flink": hex(flink),
                        "blink": hex(blink),
                        "source": "pool_scan",
                    }
                )
                break
        idx += 4
    return found


def _walk_active_process_links(
    dump_bytes: bytes,
    cr3: int,
    head_va: int,
    profile: EprocessProfile,
    phys_base: int = 0,
    max_procs: int = 1024,
) -> list[dict[str, Any]]:
    """Walk Windows ActiveProcessLinks doubly-linked list starting at PsActiveProcessHead or an EPROCESS links VA."""
    results: list[dict[str, Any]] = []
    seen_va: set[int] = set()
    cur_va = head_va
    for _ in range(max_procs):
        if cur_va in seen_va or cur_va == 0:
            break
        seen_va.add(cur_va)
        ep_va = cur_va - profile.active_process_links
        ep_bytes = _read_virtual_bytes(dump_bytes, cr3, ep_va, profile.eprocess_size, phys_base=phys_base)
        if ep_bytes is not None:
            pid = _u64(ep_bytes, profile.unique_process_id)
            name = _extract_image_name(ep_bytes[profile.image_file_name : profile.image_file_name + 15])
            dtb = _u64(ep_bytes, profile.directory_table_base)
            ct = _u64(ep_bytes, profile.create_time)
            if name and 0 <= pid <= 0x1000000:
                results.append(
                    {
                        "pid": pid,
                        "name": name,
                        "eprocess_va": hex(ep_va),
                        "dtb": hex(dtb),
                        "create_time_utc": _filetime_to_iso(ct),
                        "source": "active_process_links",
                    }
                )
        link_bytes = _read_virtual_bytes(dump_bytes, cr3, cur_va, 16, phys_base=phys_base)
        if link_bytes is None:
            break
        nxt = _u64(link_bytes, 0)
        if nxt == head_va:
            break
        cur_va = nxt
    return results


def _carve_pe_headers(
    dump_bytes: bytes,
    output_dir: Path | None = None,
    max_carve_pes: int = 8,
    reconstruct_injected: bool = False,
) -> list[dict[str, Any]]:
    """Scan physical memory for MZ/PE headers and carve valid PE images."""
    carved: list[dict[str, Any]] = []
    idx = 0
    while len(carved) < max_carve_pes:
        idx = dump_bytes.find(b"MZ", idx)
        if idx == -1:
            break
        if idx + 0x40 > len(dump_bytes):
            break
        e_lfanew = _u32(dump_bytes, idx + 0x3C)
        if 0x40 <= e_lfanew <= 0x400 and idx + e_lfanew + 0x60 <= len(dump_bytes):
            pe_off = idx + e_lfanew
            if dump_bytes[pe_off : pe_off + 4] == b"PE\x00\x00":
                machine = _u16(dump_bytes, pe_off + 4)
                num_sec = _u16(dump_bytes, pe_off + 6)
                ts = _u32(dump_bytes, pe_off + 8)
                opt_size = _u16(dump_bytes, pe_off + 20)
                if machine in (0x014C, 0x8664, 0xAA64) and 1 <= num_sec <= 32:
                    opt_off = pe_off + 24
                    size_of_image = _u32(dump_bytes, opt_off + 56) if opt_off + 60 <= len(dump_bytes) else 0x2000
                    size_of_headers = _u32(dump_bytes, opt_off + 60) if opt_off + 64 <= len(dump_bytes) else 0x400
                    sec_table_off = opt_off + opt_size
                    max_raw_end = size_of_headers
                    for s_i in range(num_sec):
                        so = sec_table_off + s_i * 40
                        if so + 40 > len(dump_bytes):
                            break
                        raw_size = _u32(dump_bytes, so + 16)
                        raw_ptr = _u32(dump_bytes, so + 20)
                        if raw_ptr + raw_size <= len(dump_bytes) - idx:
                            max_raw_end = max(max_raw_end, raw_ptr + raw_size)
                    carve_len = min(max(max_raw_end, 0x400), max(size_of_image, 0x400), len(dump_bytes) - idx, 16 * 1024 * 1024)
                    pe_blob = dump_bytes[idx : idx + carve_len]
                    entry: dict[str, Any] = {
                        "phys_offset": idx,
                        "phys_offset_hex": hex(idx),
                        "machine": hex(machine),
                        "sections": num_sec,
                        "timestamp_unix": ts,
                        "timestamp_utc": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts > 0 else None,
                        "carved_size": len(pe_blob),
                        "sha256": hashlib.sha256(pe_blob).hexdigest(),
                    }
                    if output_dir is not None:
                        carve_dir = Path(output_dir) / "carved_ram_pes"
                        carve_dir.mkdir(parents=True, exist_ok=True)
                        pe_path = carve_dir / f"carved_{idx:#x}.exe"
                        pe_path.write_bytes(pe_blob)
                        entry["carved_path"] = str(pe_path)
                        if reconstruct_injected:
                            try:
                                from aether_re.project_reconstructor import reconstruct_project

                                recon_dir = carve_dir / f"recon_{idx:#x}"
                                res = reconstruct_project(
                                    pe_path,
                                    recon_dir,
                                    max_functions=8,
                                    max_internal_subroutines=8,
                                )
                                entry["reconstructed_project_dir"] = str(recon_dir)
                                entry["reconstructed_ok"] = bool(res.get("c_files") or res.get("project_dir"))
                            except Exception as exc:  # pragma: no cover
                                entry["reconstructed_ok"] = False
                                entry["reconstruct_error"] = str(exc)
                    carved.append(entry)
                    idx += max(0x200, carve_len)
                    continue
        idx += 2
    return carved


def _detect_inline_hooks(dump_bytes: bytes, candidate_offsets: list[int] | None = None) -> list[dict[str, Any]]:
    """Detect common x64/x86 inline detour trampolines (`E9 rel32`, `FF 25`, `48 B8 .. FF E0`)."""
    hooks: list[dict[str, Any]] = []
    offsets = candidate_offsets or []
    for off in offsets:
        if off < 0 or off + 12 > len(dump_bytes):
            continue
        b = dump_bytes[off : off + 12]
        if b[0] == 0xE9:
            rel = _i32(b, 1)
            hooks.append({"offset": hex(off), "pattern": "JMP_REL32", "target_rel": rel})
        elif b[:2] == b"\xff\x25":
            hooks.append({"offset": hex(off), "pattern": "JMP_INDIRECT_FF25"})
        elif b[:2] == b"\x48\xb8" and b[10:12] == b"\xff\xe0":
            target = struct.unpack_from("<Q", b, 2)[0]
            hooks.append({"offset": hex(off), "pattern": "MOV_RAX_JMP_RAX", "target": hex(target)})
    return hooks


def analyze_physical_ram_dump(
    dump_bytes: bytes,
    output_dir: Path | str | None = None,
    cr3: int | None = None,
    active_links_head_va: int | None = None,
    eprocess_offsets: dict[str, int] | None = None,
    hook_check_offsets: list[int] | None = None,
    reconstruct_injected: bool = False,
    max_carve_pes: int = 8,
) -> dict[str, Any]:
    """Analyze a raw physical RAM dump for paging, DKOM hidden processes, RWX pages, hooks, and injected PEs."""
    out_path = Path(output_dir) if output_dir is not None else None
    profile = EprocessProfile(**(eprocess_offsets or {}))

    mapped_pages: list[dict[str, Any]] = []
    rwx_pages: list[dict[str, Any]] = []
    active_procs: list[dict[str, Any]] = []

    if cr3 is not None:
        mapped_pages = walk_pml4_pages(dump_bytes, cr3)
        rwx_pages = [p for p in mapped_pages if p.get("rwx")]
        if active_links_head_va is not None:
            active_procs = _walk_active_process_links(dump_bytes, cr3, active_links_head_va, profile)

    pool_procs = _scan_pool_eprocesses(dump_bytes, profile)
    active_pids = {int(p["pid"]) for p in active_procs}

    dkom_hidden: list[dict[str, Any]] = []
    if active_links_head_va is not None:
        for p in pool_procs:
            if int(p["pid"]) not in active_pids:
                dkom_hidden.append(
                    {
                        "finding": "DKOM_HIDDEN_PROCESS",
                        "severity": "critical",
                        "pid": p["pid"],
                        "name": p["name"],
                        "eprocess_pa": hex(p["eprocess_pa"]),
                        "dtb": p["dtb"],
                        "create_time_utc": p["create_time_utc"],
                    }
                )
    else:
        # Also detect unlinked Flink==Blink pointing to self (self-unlinked DKOM) in pool scan
        for p in pool_procs:
            ep_off = p["eprocess_pa"]
            flink = _u64(dump_bytes, ep_off + profile.active_process_links)
            blink = _u64(dump_bytes, ep_off + profile.active_process_links + 8)
            if flink != 0 and flink == blink:
                dkom_hidden.append(
                    {
                        "finding": "DKOM_SELF_UNLINKED_EPROCESS",
                        "severity": "critical",
                        "pid": p["pid"],
                        "name": p["name"],
                        "eprocess_pa": hex(ep_off),
                        "create_time_utc": p["create_time_utc"],
                    }
                )

    carved_pes = _carve_pe_headers(
        dump_bytes,
        output_dir=out_path,
        max_carve_pes=max_carve_pes,
        reconstruct_injected=reconstruct_injected,
    )

    # Check if any carved PE sits inside a physical frame mapped as RWX
    rwx_pa_frames = {p["pa_int"] & ~0xFFF for p in rwx_pages}
    for pe in carved_pes:
        pe_frame = pe["phys_offset"] & ~0xFFF
        pe["in_rwx_page"] = pe_frame in rwx_pa_frames

    inline_hooks = _detect_inline_hooks(dump_bytes, candidate_offsets=hook_check_offsets)

    return {
        "schema": "aether_ram_forensics.v1",
        "dump_size": len(dump_bytes),
        "cr3": hex(cr3) if cr3 is not None else None,
        "mapped_page_count": len(mapped_pages),
        "rwx_page_count": len(rwx_pages),
        "rwx_pages": rwx_pages[:64],
        "active_process_count": len(active_procs),
        "active_processes": active_procs,
        "pool_process_count": len(pool_procs),
        "pool_processes": pool_procs,
        "dkom_hidden_count": len(dkom_hidden),
        "dkom_hidden_processes": dkom_hidden,
        "carved_pe_count": len(carved_pes),
        "carved_pes": carved_pes,
        "inline_hooks": inline_hooks,
    }
