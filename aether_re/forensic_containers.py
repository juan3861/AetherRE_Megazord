"""Pure-Python Read-Only Forensic Containers, Filesystems & Volume Decryption (v15.0).

Supports industrial DFIR disk artifact acquisition without external mount drivers:
1. Forensic Disk Images: `.E01` (EWF `EVF` + zlib sectors), `.VHDX` (`vhdxfile` headers),
   `.VMDK` (`KDMV` descriptor), and raw GPT (`EFI PART`) / MBR (`0x55AA`) partitions.
2. Linux & Apple Filesystems: `ext4` superblock (`0xEF53`) + root directory (`inode 2`)
   walker; `APFS` container (`NXSB`) & volume (`APSB`) metadata parser.
3. Encrypted Volumes: `BitLocker` (`-FVE-FS-`) & `LUKS` header detection + AES-CBC /
   AES-ECB sector decryption using RAM-extracted or investigator-supplied FVEK keys.
"""

from __future__ import annotations

import mmap
from pathlib import Path
import struct
from typing import Any
import uuid
import zlib


def detect_forensic_container(blob: bytes | mmap.mmap) -> str:
    if len(blob) >= 8 and blob[:8] == b"EVF\x09\x0d\x0a\xff\x00":
        return "ewf_e01"
    if len(blob) >= 8 and blob[:8] == b"vhdxfile":
        return "vhdx"
    if len(blob) >= 4 and blob[:4] == b"KDMV":
        return "vmdk"
    if len(blob) >= 512 and blob[:4] == b"LUKS":
        return "luks"
    if len(blob) >= 512 and blob[3:11] == b"-FVE-FS-":
        return "bitlocker"
    if len(blob) >= 1024 and blob[512:520] == b"EFI PART":
        return "gpt_raw"
    if len(blob) >= 0x450 and struct.unpack_from("<H", blob, 0x438)[0] == 0xEF53:
        return "ext4"
    if len(blob) >= 64 and blob[0x20:0x24] == b"NXSB":
        return "apfs"
    if len(blob) >= 512 and blob[510:512] == b"\x55\xaa":
        return "mbr_raw"
    return "unknown"


def parse_ewf_e01(blob: bytes | mmap.mmap) -> dict[str, Any]:
    """Parse Expert Witness Format (`.E01`) header, sections, and multi-chunk EWF `table`."""
    if len(blob) < 13 or blob[:8] != b"EVF\x09\x0d\x0a\xff\x00":
        return {"valid": False, "sections": [], "decompressed_preview": b""}
    segment_num = struct.unpack_from("<H", blob, 9)[0]
    pos = 13
    sections: list[dict[str, Any]] = []
    decompressed_chunks: list[bytes] = []
    sectors_pos: int | None = None

    while pos + 76 <= len(blob):
        sec_type = bytes(blob[pos : pos + 16]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
        next_off, sec_size, _chk = struct.unpack_from("<QQI", blob, pos + 16)
        sections.append({"type": sec_type, "offset": pos, "next_offset": next_off, "size": sec_size})
        if sec_type == "sectors":
            sectors_pos = pos
        elif sec_type == "table" and pos + 100 <= len(blob):
            # EWF Table Section: count(u32) at +76, base_offset(u64) at +84, entries[count] u32 at +100
            entry_count = struct.unpack_from("<I", blob, pos + 76)[0]
            base_off = struct.unpack_from("<Q", blob, pos + 84)[0]
            tbl_start = pos + 100
            if 0 < entry_count <= 4096 and tbl_start + entry_count * 4 <= len(blob):
                raw_offs = [struct.unpack_from("<I", blob, tbl_start + i * 4)[0] for i in range(entry_count)]
                for i, raw_o in enumerate(raw_offs):
                    compressed = bool(raw_o & 0x80000000)
                    c_start = base_off + (raw_o & 0x7FFFFFFF)
                    c_end = (base_off + (raw_offs[i + 1] & 0x7FFFFFFF)) if i + 1 < entry_count else pos
                    if 0 <= c_start < c_end <= len(blob):
                        chunk_b = bytes(blob[c_start:c_end])
                        if compressed:
                            try:
                                decompressed_chunks.append(zlib.decompress(chunk_b))
                            except Exception:
                                pass
                        else:
                            decompressed_chunks.append(chunk_b[:-4] if len(chunk_b) > 4 else chunk_b)
        if sec_type == "done" or next_off <= pos or next_off >= len(blob):
            break
        pos = next_off

    if not decompressed_chunks and sectors_pos is not None:
        body = bytes(blob[sectors_pos + 76 : min(len(blob), sectors_pos + 65536)])
        z_off = body.find(b"\x78\x9c")
        if z_off == -1:
            z_off = body.find(b"\x78\xda")
        if z_off != -1:
            try:
                decompressed_chunks.append(zlib.decompress(body[z_off:]))
            except Exception:
                pass

    return {
        "schema": "aether_ewf_e01.v1",
        "valid": True,
        "segment_number": segment_num,
        "sections": sections,
        "chunks_reconstructed": len(decompressed_chunks),
        "decompressed_bytes_count": sum(len(c) for c in decompressed_chunks),
        "decompressed_preview": b"".join(decompressed_chunks)[:4096],
    }


def parse_vhdx_image(blob: bytes | mmap.mmap) -> dict[str, Any]:
    """Parse VHDX file identifier, Region Table (`regi`), and BAT (Block Allocation Table) entries."""
    if len(blob) < 0x40000 or blob[:8] != b"vhdxfile":
        return {"valid": blob[:8] == b"vhdxfile" if len(blob) >= 8 else False, "regions": [], "bat_entries_present": 0}
    creator = bytes(blob[8:72]).decode("utf-16le", errors="ignore").strip("\x00")
    regions: list[dict[str, Any]] = []
    bat_offset: int | None = None
    bat_len = 0
    for reg_off in (0x30000, 0x40000):
        if reg_off + 32 <= len(blob) and blob[reg_off : reg_off + 4] == b"regi":
            cnt = struct.unpack_from("<I", blob, reg_off + 8)[0]
            for i in range(min(cnt, 64)):
                eo = reg_off + 16 + i * 32
                if eo + 32 > len(blob):
                    break
                r_guid = str(uuid.UUID(bytes_le=bytes(blob[eo : eo + 16]))).upper()
                f_off, length, req = struct.unpack_from("<QII", blob, eo + 16)
                regions.append({"guid": r_guid, "file_offset": f_off, "length": length, "required": bool(req)})
                if r_guid == "2DC27766-F623-4200-9D64-115E9BFD4A08":  # BAT Region GUID
                    bat_offset, bat_len = f_off, length
            break

    present_blocks: list[dict[str, int]] = []
    if bat_offset is not None and bat_offset + 8 <= len(blob):
        n_ents = min(bat_len // 8 if bat_len else 64, (len(blob) - bat_offset) // 8, 1024)
        for idx in range(n_ents):
            val = struct.unpack_from("<Q", blob, bat_offset + idx * 8)[0]
            state = val & 0x7
            phys_mb_off = (val >> 20) << 20
            if state == 6 and phys_mb_off > 0:  # PAYLOAD_BLOCK_FULLY_PRESENT
                present_blocks.append({"block_index": idx, "file_offset": phys_mb_off})

    return {
        "schema": "aether_vhdx.v1",
        "valid": True,
        "creator_utf16": creator,
        "regions": regions,
        "bat_entries_present": len(present_blocks),
        "present_blocks": present_blocks[:64],
    }


def parse_gpt_mbr_partitions(disk_blob: bytes | mmap.mmap, sector_size: int = 512) -> dict[str, Any]:
    """Parse protective MBR (`0x55AA`) and GPT (`EFI PART`) partition entries."""
    partitions: list[dict[str, Any]] = []
    has_mbr = len(disk_blob) >= 512 and disk_blob[510:512] == b"\x55\xaa"
    if has_mbr:
        for idx in range(4):
            off = 446 + idx * 16
            part_type = disk_blob[off + 4]
            lba_start, lba_count = struct.unpack_from("<II", disk_blob, off + 8)
            if part_type != 0 and lba_count > 0:
                partitions.append({
                    "scheme": "mbr",
                    "index": idx,
                    "type": hex(part_type),
                    "start_lba": lba_start,
                    "sectors": lba_count,
                    "name": "PROTECTIVE_GPT" if part_type == 0xEE else f"MBR_{part_type:02X}",
                })

    gpt_off = sector_size
    has_gpt = len(disk_blob) >= gpt_off + 92 and disk_blob[gpt_off : gpt_off + 8] == b"EFI PART"
    if has_gpt:
        part_entry_lba = struct.unpack_from("<Q", disk_blob, gpt_off + 72)[0]
        num_entries, entry_sz = struct.unpack_from("<II", disk_blob, gpt_off + 80)
        base_ent = part_entry_lba * sector_size
        for idx in range(min(num_entries, 128)):
            eo = base_ent + idx * entry_sz
            if eo + entry_sz > len(disk_blob):
                break
            type_guid_b = bytes(disk_blob[eo : eo + 16])
            if type_guid_b == b"\x00" * 16:
                continue
            first_lba, last_lba, attrs = struct.unpack_from("<QQQ", disk_blob, eo + 32)
            name_raw = bytes(disk_blob[eo + 56 : eo + min(entry_sz, 128)])
            pname = name_raw.decode("utf-16le", errors="replace").split("\x00", 1)[0]
            partitions.append({
                "scheme": "gpt",
                "index": idx,
                "type_guid": str(uuid.UUID(bytes_le=type_guid_b)),
                "start_lba": first_lba,
                "sectors": max(0, last_lba - first_lba + 1),
                "attributes": hex(attrs),
                "name": pname,
            })

    return {
        "schema": "aether_partitions.v1",
        "has_mbr": has_mbr,
        "has_gpt": has_gpt,
        "partition_count": len(partitions),
        "partitions": partitions,
    }


def parse_ext4_superblock_and_root(fs_blob: bytes | mmap.mmap) -> dict[str, Any]:
    """Parse Linux `ext4` superblock (`0xEF53` at offset 0x438) & directory entries."""
    if len(fs_blob) < 0x500 or struct.unpack_from("<H", fs_blob, 0x438)[0] != 0xEF53:
        return {"schema": "aether_ext4.v1", "valid": False, "entries": []}
    inodes_count, blocks_count = struct.unpack_from("<II", fs_blob, 0x400)
    log_block_size = struct.unpack_from("<I", fs_blob, 0x418)[0]
    block_size = 1024 << min(log_block_size, 6)
    blocks_per_group, _frag, inodes_per_group = struct.unpack_from("<III", fs_blob, 0x420)
    vol_name = bytes(fs_blob[0x478 : 0x488]).split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    # 1. Try real Block Group Descriptor Table -> Inode Table -> Inode 2 Extent Tree (0xF30A)
    inode_size = struct.unpack_from("<H", fs_blob, 0x458)[0] or 256
    bgdt_off = block_size if block_size > 1024 else 2048
    extent_blocks: list[int] = []
    inode_tbl_off: int | None = None
    if bgdt_off + 32 <= len(fs_blob):
        it_blk = struct.unpack_from("<I", fs_blob, bgdt_off + 8)[0]
        if it_blk > 0 and it_blk * block_size + inode_size * 2 <= len(fs_blob):
            inode_tbl_off = it_blk * block_size
            root_ino_off = inode_tbl_off + inode_size  # inode #2 (1-based)
            if root_ino_off + 64 <= len(fs_blob):
                i_blk = root_ino_off + 40
                eh_magic, eh_entries = struct.unpack_from("<HH", fs_blob, i_blk)
                if eh_magic == 0xF30A and 0 < eh_entries <= 4:
                    for ei in range(eh_entries):
                        eo = i_blk + 12 + ei * 12
                        _ee_blk, ee_len, ee_hi, ee_lo = struct.unpack_from("<IHHI", fs_blob, eo)
                        phys_blk = (ee_hi << 32) | ee_lo
                        for b_i in range(min(ee_len, 16)):
                            extent_blocks.append((phys_blk + b_i) * block_size)

    entries: list[dict[str, Any]] = []
    scan_bases = extent_blocks if extent_blocks else sorted({block_size, block_size * 2, 0x2000, 0x3000})
    for base in scan_bases:
        if base + 64 > len(fs_blob):
            continue
        pos = base
        block_end = min(len(fs_blob), base + block_size)
        blk_entries: list[dict[str, Any]] = []
        while pos + 8 <= block_end:
            inode, rec_len, name_len, ftype = struct.unpack_from("<IHBB", fs_blob, pos)
            if rec_len < 8 or pos + rec_len > block_end:
                break
            if inode > 0 and 1 <= name_len <= 255 and ftype in (1, 2, 7) and pos + 8 + name_len <= block_end:
                fname = bytes(fs_blob[pos + 8 : pos + 8 + name_len]).decode("utf-8", errors="replace")
                if fname and all(32 <= ord(c) < 127 for c in fname):
                    ent: dict[str, Any] = {"inode": inode, "name": fname, "file_type": {1: "file", 2: "dir", 7: "symlink"}.get(ftype, "other")}
                    # Extract file payload from its Inode Extent Tree when inode table is present
                    if ftype == 1 and inode_tbl_off is not None:
                        f_ino = inode_tbl_off + (inode - 1) * inode_size
                        if f_ino + 64 <= len(fs_blob):
                            f_sz = struct.unpack_from("<I", fs_blob, f_ino + 4)[0]
                            f_em, f_ec = struct.unpack_from("<HH", fs_blob, f_ino + 40)
                            if f_em == 0xF30A and f_ec >= 1:
                                _, _, f_hi, f_lo = struct.unpack_from("<IHHI", fs_blob, f_ino + 52)
                                f_off = ((f_hi << 32) | f_lo) * block_size
                                if f_off + f_sz <= len(fs_blob):
                                    ent["size"] = f_sz
                                    ent["content_preview"] = bytes(fs_blob[f_off : f_off + min(f_sz, 256)]).decode("utf-8", errors="replace")
                    blk_entries.append(ent)
            pos += rec_len
        if extent_blocks or any(e["name"] in (".", "..") for e in blk_entries) or len(blk_entries) >= 2:
            entries.extend(blk_entries)

    return {
        "schema": "aether_ext4.v1",
        "valid": True,
        "used_extent_tree": bool(extent_blocks),
        "volume_name": vol_name,
        "block_size": block_size,
        "inodes_count": inodes_count,
        "blocks_count": blocks_count,
        "inodes_per_group": inodes_per_group,
        "entries": entries,
    }


def parse_apfs_container(apfs_blob: bytes | mmap.mmap) -> dict[str, Any]:
    """Parse Apple APFS container superblock (`NXSB`) and volume superblock (`APSB`)."""
    if len(apfs_blob) < 0x100 or apfs_blob[0x20:0x24] != b"NXSB":
        return {"schema": "aether_apfs.v1", "valid": False}
    block_size, block_count = struct.unpack_from("<IQ", apfs_blob, 0x24)
    has_apsb = b"APSB" in bytes(apfs_blob[: min(len(apfs_blob), 0x10000)])
    return {
        "schema": "aether_apfs.v1",
        "valid": True,
        "block_size": block_size,
        "block_count": block_count,
        "has_volume_apsb": has_apsb,
    }


def decrypt_bitlocker_xts_sector(
    sector_cipher: bytes,
    xts_fvek_key: bytes,
    sector_index: int,
) -> bytes:
    """Decrypt a Windows 10/11 BitLocker AES-XTS encrypted sector (32B AES-128-XTS or 64B AES-256-XTS)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    tweak = struct.pack("<QQ", sector_index, 0)
    dec = Cipher(algorithms.AES(xts_fvek_key), modes.XTS(tweak)).decryptor()
    return dec.update(sector_cipher) + dec.finalize()


def decrypt_bitlocker_sector_with_fvek(
    sector_cipher: bytes,
    fvek_key: bytes,
    sector_offset: int,
) -> bytes:
    """Decrypt a BitLocker AES-CBC encrypted sector using RAM-extracted FVEK (16/32 bytes)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv_plain = struct.pack("<Q", sector_offset) + b"\x00" * 8
    # Standard AES-CBC with sector-offset derived IV using FVEK key
    enc_iv = Cipher(algorithms.AES(fvek_key[: len(fvek_key)]), modes.ECB()).encryptor()
    iv = enc_iv.update(iv_plain) + enc_iv.finalize()
    dec = Cipher(algorithms.AES(fvek_key[: len(fvek_key)]), modes.CBC(iv[:16])).decryptor()
    return dec.update(sector_cipher) + dec.finalize()


def analyze_forensic_image(
    image_path: str | Path,
    *,
    fvek_key: bytes | None = None,
) -> dict[str, Any]:
    """Zero-copy mmap analyzer for `.E01`, `.VHDX`, `.VMDK`, GPT/MBR, `ext4`, `APFS`, and `BitLocker`."""
    p = Path(image_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Forensic image not found: {p}")
    size = p.stat().st_size
    if size == 0:
        return {"schema": "aether_forensic_container.v1", "format": "empty", "size_bytes": 0}

    with p.open("rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            fmt = detect_forensic_container(mm)
            out: dict[str, Any] = {
                "schema": "aether_forensic_container.v1",
                "path": str(p),
                "size_bytes": size,
                "format": fmt,
                "zero_copy_mmap": True,
            }
            if fmt == "ewf_e01":
                out["ewf"] = {k: v for k, v in parse_ewf_e01(mm).items() if k != "decompressed_preview"}
            elif fmt == "vhdx":
                out["vhdx"] = parse_vhdx_image(mm)
            elif fmt == "vmdk":
                out["vmdk"] = {"valid": True, "version": struct.unpack_from("<I", mm, 4)[0] if size >= 8 else 1}
            elif fmt == "ext4":
                out["ext4"] = parse_ext4_superblock_and_root(mm)
            elif fmt == "apfs":
                out["apfs"] = parse_apfs_container(mm)
            elif fmt == "bitlocker":
                out["bitlocker"] = {"detected": True, "fvek_supplied": fvek_key is not None}
                if fvek_key is not None and size >= 1024:
                    out["bitlocker"]["decrypted_sample_hex"] = decrypt_bitlocker_sector_with_fvek(bytes(mm[512:1024]), fvek_key, 512)[:64].hex()
            if fmt in {"gpt_raw", "mbr_raw"} or (size >= 1024 and mm[510:512] == b"\x55\xaa"):
                out["partitions"] = parse_gpt_mbr_partitions(mm)
            return out
