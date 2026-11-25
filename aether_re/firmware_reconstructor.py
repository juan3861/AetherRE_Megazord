"""AetherRE Megazord v8.0 — Firmware, RootFS, MMIO Re-Hosting & Windows Kernel Driver Reconstructor."""

from __future__ import annotations

import gzip
import io
import json
import lzma
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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


def _parse_squashfs_v4(blob: bytes, out_dir: Path, rootfs_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Pure-Python SquashFS v4 (`hsqs`) superblock, metadata, directory tree & data extractor."""
    sq_off = blob.find(b"hsqs")
    if sq_off == -1 or sq_off + 96 > len(blob):
        return {"found": False, "extracted_files": []}
    (
        magic, inodes, mkfs_time, block_size, frag_cnt, comp_id,
        block_log, flags, no_ids, s_major, s_minor, root_inode_ref,
        bytes_used, id_tbl, xattr_tbl, inode_tbl, dir_tbl, frag_tbl, export_tbl,
    ) = struct.unpack_from("<IIIIIHHHHHHQQQQQQQQ", blob, sq_off)
    if magic != 0x73717368 or s_major != 4 or block_size == 0:
        return {"found": False, "extracted_files": []}

    comp_names = {1: "gzip/zlib", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}

    def _decompress_chunk(chunk: bytes, is_uncompressed: bool) -> bytes:
        if is_uncompressed:
            return chunk
        try:
            if comp_id == 1:
                return zlib.decompress(chunk)
            if comp_id in (2, 4):
                return lzma.decompress(chunk)
        except Exception:
            return b""
        return chunk

    def _read_meta_chain(table_base_rel: int, start_block_rel: int, inner_off: int, min_bytes: int) -> bytes:
        """Reads consecutive SquashFS metadata blocks (up to 8 KiB uncompressed each) starting at table_base_rel + start_block_rel."""
        cur_rel = table_base_rel + start_block_rel
        chunks: List[bytes] = []
        total_len = 0
        for _ in range(128):
            abs_p = sq_off + cur_rel
            if abs_p + 2 > len(blob):
                break
            hdr_u16 = struct.unpack_from("<H", blob, abs_p)[0]
            uncomp = bool(hdr_u16 & 0x8000)
            sz = hdr_u16 & 0x7FFF
            if sz == 0 or abs_p + 2 + sz > len(blob):
                break
            dec = _decompress_chunk(blob[abs_p + 2 : abs_p + 2 + sz], uncomp)
            if not dec:
                break
            chunks.append(dec)
            total_len += len(dec)
            cur_rel += 2 + sz
            if total_len >= inner_off + min_bytes:
                break
        joined = b"".join(chunks)
        return joined[inner_off:] if inner_off < len(joined) else b""

    def _read_data_block(abs_rel_off: int, size_word: int) -> bytes:
        sz = size_word & 0x00FFFFFF
        uncomp = bool(size_word & 0x01000000)
        if sz == 0:  # sparse zero block
            return b"\x00" * block_size
        abs_p = sq_off + abs_rel_off
        if abs_p + sz > len(blob):
            return b""
        return _decompress_chunk(blob[abs_p : abs_p + sz], uncomp)

    # Parse fragment entries if present
    frag_entries: List[Tuple[int, int]] = []
    if frag_cnt > 0 and frag_tbl != 0xFFFFFFFFFFFFFFFF and sq_off + frag_tbl + 8 <= len(blob):
        n_frag_blks = (frag_cnt + 511) // 512
        for fi in range(min(n_frag_blks, 32)):
            ptr_off = sq_off + frag_tbl + fi * 8
            if ptr_off + 8 > len(blob):
                break
            blk_rel = struct.unpack_from("<Q", blob, ptr_off)[0]
            fmeta = _read_meta_chain(0, blk_rel, 0, min(512, frag_cnt - fi * 512) * 16)
            for j in range(0, len(fmeta) - 15, 16):
                f_start, f_sz, _ = struct.unpack_from("<QII", fmeta, j)
                frag_entries.append((f_start, f_sz))

    meta_strings: List[str] = []
    dir_meta = _read_meta_chain(dir_tbl, 0, 0, 8192)
    if dir_meta:
        (out_dir / "squashfs_dir_meta.bin").write_bytes(dir_meta)
        pos_d = 0
        while pos_d + 8 <= len(dir_meta):
            m_end = 0
            if 32 <= dir_meta[pos_d] < 127:
                while pos_d + m_end < len(dir_meta) and 32 <= dir_meta[pos_d + m_end] < 127:
                    m_end += 1
                if m_end >= 3:
                    meta_strings.append(dir_meta[pos_d : pos_d + m_end].decode("ascii", errors="replace"))
                    pos_d += m_end
                    continue
            pos_d += 1

    extracted_files: List[str] = []
    symlinks: Dict[str, str] = {}
    if rootfs_dir is not None:
        rootfs_res = rootfs_dir.resolve()
        visited_inodes: Set[int] = set()

        def _walk_inode(inode_ref: int, rel_path: Path, depth: int = 0) -> None:
            if depth > 32 or inode_ref in visited_inodes:
                return
            visited_inodes.add(inode_ref)
            blk_rel = (inode_ref >> 16) & 0xFFFFFFFFFFFF
            inner_off = inode_ref & 0xFFFF
            ibuf = _read_meta_chain(inode_tbl, blk_rel, inner_off, 1024)
            if len(ibuf) < 16:
                return
            i_type, _mode, _uid, _gid, _mtime, _ino_num = struct.unpack_from("<HHIHHI", ibuf, 0)

            if i_type in (1, 8):  # Basic / Extended Directory
                if i_type == 1 and len(ibuf) >= 32:
                    d_start, _nlink, d_fsize, d_off, _parent = struct.unpack_from("<IIHHI", ibuf, 16)
                elif i_type == 8 and len(ibuf) >= 40:
                    _nlink, d_fsize, d_start, _parent, _icnt, d_off, _xattr = struct.unpack_from("<IIIIHHI", ibuf, 16)
                else:
                    return
                dir_bytes_len = max(0, int(d_fsize) - 3)
                if dir_bytes_len == 0:
                    return
                dbuf = _read_meta_chain(dir_tbl, d_start, d_off, dir_bytes_len)[:dir_bytes_len]
                dp = 0
                while dp + 12 <= len(dbuf):
                    cnt_m1, hdr_blk, _ino_base = struct.unpack_from("<III", dbuf, dp)
                    dp += 12
                    for _ in range(min(cnt_m1 + 1, 2048)):
                        if dp + 8 > len(dbuf):
                            return
                        e_off, _e_delta, _e_type, e_nsz_m1 = struct.unpack_from("<HhHH", dbuf, dp)
                        dp += 8
                        nlen = e_nsz_m1 + 1
                        if dp + nlen > len(dbuf):
                            return
                        ename = dbuf[dp : dp + nlen].decode("utf-8", errors="replace")
                        dp += nlen
                        if not ename or ename in (".", "..") or "/" in ename or "\\" in ename:
                            continue
                        child_ref = (hdr_blk << 16) | e_off
                        _walk_inode(child_ref, rel_path / ename, depth + 1)

            elif i_type in (2, 9):  # Basic / Extended Regular File
                if i_type == 2 and len(ibuf) >= 32:
                    b_start, frag_idx, f_off, f_size = struct.unpack_from("<IIII", ibuf, 16)
                    list_off = 32
                elif i_type == 9 and len(ibuf) >= 56:
                    b_start, f_size, _sparse, _nlink, frag_idx, f_off, _xattr = struct.unpack_from("<QQQIIII", ibuf, 16)
                    list_off = 56
                else:
                    return
                has_frag = frag_idx != 0xFFFFFFFF
                n_full_blks = (f_size // block_size) if has_frag else ((f_size + block_size - 1) // block_size)
                # Clamp if inode spans beyond initial 1024-byte buffer
                needed_bytes = list_off + n_full_blks * 4
                if needed_bytes > len(ibuf):
                    ibuf = _read_meta_chain(inode_tbl, blk_rel, inner_off, needed_bytes)
                file_parts: List[bytes] = []
                cur_data_rel = int(b_start)
                for bi in range(n_full_blks):
                    if list_off + (bi + 1) * 4 > len(ibuf):
                        break
                    sz_word = struct.unpack_from("<I", ibuf, list_off + bi * 4)[0]
                    raw_blk = _read_data_block(cur_data_rel, sz_word)
                    file_parts.append(raw_blk)
                    cur_data_rel += sz_word & 0x00FFFFFF
                if has_frag and frag_idx < len(frag_entries):
                    rem = f_size % block_size
                    if rem > 0 or f_size == 0:
                        f_blk_rel, f_sz_word = frag_entries[frag_idx]
                        frag_buf = _read_data_block(f_blk_rel, f_sz_word)
                        file_parts.append(frag_buf[f_off : f_off + rem])
                payload = b"".join(file_parts)[:f_size]
                if rel_path.parts and ".." not in rel_path.parts:
                    dest = (rootfs_dir / rel_path).resolve()
                    if str(dest).startswith(str(rootfs_res)):
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(payload)
                        extracted_files.append(rel_path.as_posix())

            elif i_type in (3, 10) and len(ibuf) >= 24:  # Symlink
                _nlink, sl_sz = struct.unpack_from("<II", ibuf, 16)
                tgt = ibuf[24 : 24 + sl_sz].decode("utf-8", errors="replace")
                if rel_path.parts:
                    symlinks[rel_path.as_posix()] = tgt

        if root_inode_ref:
            _walk_inode(int(root_inode_ref), Path())

    return {
        "found": True,
        "offset_hex": hex(sq_off),
        "inodes": int(inodes),
        "block_size": int(block_size),
        "compression": comp_names.get(comp_id, f"unknown_{comp_id}"),
        "bytes_used": int(bytes_used),
        "dir_entries_hints": meta_strings[:64],
        "extracted_files": extracted_files,
        "symlinks": symlinks,
    }


def _parse_fdt_dtb(blob: bytes) -> Dict[str, Any]:
    """Parses Flattened Device Tree (.dtb, magic 0xD00DFEED) extracting memory & MMIO `reg` regions."""
    pos = blob.find(b"\xD0\x0D\xFE\xED")
    if pos == -1 or pos + 40 > len(blob):
        return {"found": False, "nodes": [], "mmio_regions": []}
    magic, totalsize, off_struct, off_strings, off_rsv, version, _last_comp, _boot_cpu, sz_strings, sz_struct = struct.unpack_from(">10I", blob, pos)
    if magic != 0xD00DFEED or totalsize < 40 or pos + totalsize > len(blob):
        return {"found": False, "nodes": [], "mmio_regions": []}

    str_tbl = blob[pos + off_strings : pos + off_strings + sz_strings]
    st_buf = blob[pos + off_struct : pos + off_struct + sz_struct]
    p = 0
    stack: List[str] = []
    nodes: List[Dict[str, Any]] = []
    mmio_regions: List[Dict[str, str]] = []
    cur_props: Dict[str, Any] = {}

    while p + 4 <= len(st_buf):
        tok = struct.unpack_from(">I", st_buf, p)[0]
        p += 4
        if tok == 1:  # FDT_BEGIN_NODE
            nul = st_buf.find(b"\x00", p)
            if nul == -1:
                break
            nm = st_buf[p:nul].decode("utf-8", errors="replace") or "/"
            p = (nul + 4) & ~3
            stack.append(nm)
            cur_props = {}
        elif tok == 2:  # FDT_END_NODE
            path_str = "/" + "/".join(x for x in stack if x != "/")
            if stack:
                nodes.append({"path": path_str or "/", "props": dict(cur_props)})
                stack.pop()
            cur_props = {}
        elif tok == 3 and p + 8 <= len(st_buf):  # FDT_PROP
            plen, nameoff = struct.unpack_from(">II", st_buf, p)
            p += 8
            pval = st_buf[p : p + plen]
            p = (p + plen + 3) & ~3
            nul_s = str_tbl.find(b"\x00", nameoff)
            pname = str_tbl[nameoff : nul_s if nul_s != -1 else len(str_tbl)].decode("utf-8", errors="replace")
            if pname == "compatible":
                cur_props[pname] = pval.rstrip(b"\x00").decode("utf-8", errors="replace")
            elif pname == "reg" and len(pval) >= 8:
                base_a, sz_a = struct.unpack_from(">II", pval, 0)
                cur_props["reg"] = f"{hex(base_a)}+{hex(sz_a)}"
                mmio_regions.append({"node": stack[-1] if stack else "root", "base": hex(base_a), "size": hex(sz_a)})
        elif tok == 4:  # FDT_NOP
            continue
        elif tok == 9:  # FDT_END
            break
        else:
            break

    return {"found": True, "offset_hex": hex(pos), "version": version, "nodes": nodes, "mmio_regions": mmio_regions}


def _parse_uefi_fv(blob: bytes) -> Dict[str, Any]:
    """Parses UEFI PI Firmware Volumes (`_FVH` at +40) and extracts FFS module GUIDs, PEIM/DXE/SMM types."""
    sig_off = blob.find(b"_FVH")
    if sig_off < 40:
        return {"found": False, "modules": []}
    fv_start = sig_off - 40
    if fv_start + 64 > len(blob):
        return {"found": False, "modules": []}
    fv_len, sig, attrs, hdr_len = struct.unpack_from("<QIIH", blob, fv_start + 32)
    if sig != 0x4856465F or hdr_len < 48:
        return {"found": False, "modules": []}

    fv_end = min(len(blob), fv_start + max(fv_len, hdr_len))
    cur = (fv_start + hdr_len + 7) & ~7
    ffs_types = {0x06: "PEI_CORE", 0x07: "PEIM", 0x05: "DXE_CORE", 0x07: "PEIM", 0x0A: "SMM_CORE", 0x0C: "MM_STANDALONE", 0x07: "DRIVER"}
    type_names = {0x03: "SECURITY_CORE", 0x04: "PEI_CORE", 0x05: "DXE_CORE", 0x06: "PEIM", 0x07: "DXE_DRIVER", 0x08: "COMBINED_PEIM_DRIVER", 0x09: "APPLICATION", 0x0A: "SMM_DRIVER", 0x0B: "FIRMWARE_VOLUME_IMAGE"}
    modules: List[Dict[str, Any]] = []
    while cur + 24 <= fv_end:
        guid_raw = blob[cur : cur + 16]
        if guid_raw == b"\xFF" * 16:
            break
        ftype = blob[cur + 18]
        sz_b = blob[cur + 20 : cur + 23]
        fsize = sz_b[0] | (sz_b[1] << 8) | (sz_b[2] << 16)
        if fsize < 24 or cur + fsize > fv_end:
            break
        d1, d2, d3 = struct.unpack_from("<IHH", guid_raw, 0)
        guid_str = f"{d1:08x}-{d2:04x}-{d3:04x}-{guid_raw[8:10].hex()}-{guid_raw[10:16].hex()}"
        mod_bytes = blob[cur + 24 : cur + fsize]
        has_smm_risk = (ftype == 0x0A) and (b"gBS" in mod_bytes or b"LocateProtocol" in mod_bytes or b"MZ" in mod_bytes)
        modules.append({
            "guid": guid_str,
            "type_id": hex(ftype),
            "type_name": type_names.get(ftype, f"FFS_{ftype:#x}"),
            "size_bytes": fsize,
            "has_embedded_pe": b"MZ" in mod_bytes,
            "smm_callout_candidate": has_smm_risk,
        })
        cur = (cur + fsize + 7) & ~7

    return {"found": True, "fv_offset": hex(fv_start), "fv_length": fv_len, "modules_count": len(modules), "modules": modules}


def _detect_embedded_filesystems(blob: bytes) -> List[Dict[str, Any]]:
    """Detects CramFS, JFFS2, UBI/UBIFS, and EXT2/3/4 embedded firmware filesystems."""
    hits: List[Dict[str, Any]] = []
    if struct.unpack_from("<I", blob, 0)[0] == 0x28CD3D45 or b"\x45\x3d\xcd\x28" in blob[:4096]:
        hits.append({"filesystem": "cramfs", "magic": "0x28cd3d45"})
    if b"UBI#" in blob:
        hits.append({"filesystem": "ubi_ubifs", "offset": hex(blob.find(b"UBI#"))})
    if len(blob) >= 1082 and struct.unpack_from("<H", blob, 1080)[0] == 0xEF53:
        hits.append({"filesystem": "ext2_3_4", "offset": "0x400"})
    jpos = blob.find(b"\x85\x19")
    if jpos != -1:
        hits.append({"filesystem": "jffs2", "offset": hex(jpos)})
    return hits


def reconstruct_firmware_project(
    target_path: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Extracts firmware containers/rootfs/DTB/UEFI/uImage and emits multi-arch Unicorn MMIO re-hosting scaffold."""
    t_path = Path(target_path).resolve()
    out_root = Path(output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    raw = t_path.read_bytes()

    fw_report = analyze_firmware(raw)
    dtb_info = _parse_fdt_dtb(raw)
    uefi_info = _parse_uefi_fv(raw)
    ext_fs = _detect_embedded_filesystems(raw)
    generated: List[str] = []

    rootfs_dir = out_root / "rootfs"
    rootfs_dir.mkdir(parents=True, exist_ok=True)
    cpio_files = _extract_cpio_newc(raw, rootfs_dir)
    for cf in cpio_files:
        generated.append(f"rootfs/{cf}")

    sq_info = _parse_squashfs_v4(raw, out_root, rootfs_dir=rootfs_dir)
    if (out_root / "squashfs_dir_meta.bin").is_file():
        generated.append("squashfs_dir_meta.bin")
    sq_files = list(sq_info.get("extracted_files", []))
    for sf in sq_files:
        rel_sf = f"rootfs/{sf}"
        if rel_sf not in generated:
            generated.append(rel_sf)

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

    total_rootfs_files = len(cpio_files) + len(sq_files)
    mmio_map = {
        "schema": SCHEMA,
        "firmware_findings": fw_report,
        "squashfs_v4": sq_info,
        "dtb_device_tree": dtb_info,
        "uefi_firmware_volume": uefi_info,
        "embedded_filesystems": ext_fs,
        "mmio_peripheral_pages": [hex(a) for a in sorted(mmio_addrs)],
        "rootfs_files_extracted": total_rootfs_files,
    }
    (out_root / "mmio_peripheral_map.json").write_text(json.dumps(mmio_map, indent=2), encoding="utf-8")
    generated.append("mmio_peripheral_map.json")

    rehost_dir = out_root / "rehosting"
    rehost_dir.mkdir(parents=True, exist_ok=True)
    dtb_bank_lines = [
        f"    # DTB Auto-Mapped Region `{r['node']}`: {r['base']} ({r['size']})"
        for r in dtb_info.get("mmio_regions", [])[:16]
    ]
    harness_py = "\n".join([
        '"""Auto-Generated Multi-Arch Fuzzware-Style Unicorn MMIO Re-Hosting Harness (AetherRE v11.0)."""',
        "from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_ALL, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE",
        "",
        "def create_rehost_uc(fw_bytes: bytes, load_addr: int = 0x08000000):",
        "    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)",
        "    uc.mem_map(load_addr, max(0x10000, ((len(fw_bytes) + 0xFFF) & ~0xFFF)), UC_PROT_ALL)",
        "    uc.mem_write(load_addr, fw_bytes)",
        "    uc.mem_map(0x40000000, 0x01000000, UC_PROT_ALL)  # MMIO peripheral bank",
        "    uc.mem_map(0x20000000, 0x00100000, UC_PROT_ALL)  # SRAM",
        *dtb_bank_lines,
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
        "rootfs_files_count": total_rootfs_files,
        "dtb_found": bool(dtb_info.get("found")),
        "uefi_found": bool(uefi_info.get("found")),
        "uefi_modules_count": int(uefi_info.get("modules_count", 0)),
        "embedded_filesystems": ext_fs,
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
