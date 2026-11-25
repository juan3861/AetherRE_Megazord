"""Read-Only Disk, NTFS $MFT, Windows Registry Hive, EVTX & Prefetch Forensics (v11.5).

Pure-Python forensic artifact dissectors:
1. NTFS `$MFT` (`FILE` record parser + USA fixups + `$STANDARD_INFORMATION` 0x10 vs
   `$FILE_NAME` 0x30 extraction + timestomping conflict detection).
2. Windows Registry Hive (`regf` / `hbin` / `nk` / `vk` / `lf` / `lh` / `li` / `ri`)
   recursive key & value parser with persistence/Run/Services tagging.
3. Windows Event Log `.evtx` (`ElfFile` / `ElfChnk` / event records) binary XML &
   UTF-16LE event extractor with EventID + MITRE ATT&CK enrichment.
4. Windows Prefetch (`SCCA`) execution artifact parser.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re
import struct
from typing import Any


_FILETIME_EPOCH_DIFF = 116444736000000000
_PERSISTENCE_KEY_TOKENS = ("run", "runonce", "services", "userinit", "shell", "appinit_dlls", "image file execution")

_EVENT_MITRE = {
    4624: ("Initial Access / Lateral Movement", "T1078", "Valid Accounts Logon"),
    4625: ("Credential Access", "T1110", "Failed Logon / Brute Force"),
    4688: ("Execution", "T1059", "Process Creation"),
    7045: ("Persistence", "T1543.003", "Windows Service Installed"),
    1102: ("Defense Evasion", "T1070.001", "Audit Log Cleared"),
    1: ("Execution", "T1059", "Sysmon Process Create"),
    3: ("Command and Control", "T1071", "Sysmon Network Connect"),
    11: ("Persistence / Execution", "T1105", "Sysmon FileCreate"),
}


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def _i32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<i", buf, off)[0]


def filetime_to_iso(ft: int) -> str | None:
    if ft <= _FILETIME_EPOCH_DIFF or ft > 0x02FFFFFFFFFFFFFF:
        return None
    us = (ft - _FILETIME_EPOCH_DIFF) // 10
    try:
        return datetime.fromtimestamp(us / 1_000_000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return None


def _apply_mft_usa_fixup(rec: bytearray) -> None:
    usa_off = _u16(rec, 4)
    usa_count = _u16(rec, 6)
    if usa_off < 42 or usa_count < 2 or usa_off + usa_count * 2 > len(rec):
        return
    usn = rec[usa_off : usa_off + 2]
    for sector_idx in range(1, usa_count):
        sector_end = sector_idx * 512 - 2
        if sector_end + 2 > len(rec):
            break
        if rec[sector_end : sector_end + 2] == usn:
            rep_off = usa_off + sector_idx * 2
            rec[sector_end : sector_end + 2] = rec[rep_off : rep_off + 2]


def parse_mft_records(mft_bytes: bytes, record_size: int = 1024) -> dict[str, Any]:
    """Parse NTFS `$MFT` records and detect `$SI` vs `$FN` timestomping."""
    entries: list[dict[str, Any]] = []
    timestomped: list[dict[str, Any]] = []

    total = len(mft_bytes) // record_size
    for idx in range(total):
        raw = mft_bytes[idx * record_size : (idx + 1) * record_size]
        if raw[:4] != b"FILE":
            continue
        rec = bytearray(raw)
        _apply_mft_usa_fixup(rec)
        flags = _u16(rec, 0x16)
        attr_off = _u16(rec, 0x14)
        if attr_off < 0x20 or attr_off >= len(rec):
            continue

        si_times: dict[str, int] | None = None
        fn_candidates: list[dict[str, Any]] = []

        pos = attr_off
        while pos + 16 <= len(rec):
            attr_type = _u32(rec, pos)
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = _u32(rec, pos + 4)
            if attr_len < 16 or pos + attr_len > len(rec):
                break
            non_resident = rec[pos + 8]
            if non_resident == 0 and pos + 24 <= len(rec):
                c_len = _u32(rec, pos + 16)
                c_off = _u16(rec, pos + 20)
                c_abs = pos + c_off
                if c_abs + c_len <= pos + attr_len:
                    if attr_type == 0x10 and c_len >= 32:
                        si_times = {
                            "created": _u64(rec, c_abs),
                            "modified": _u64(rec, c_abs + 8),
                            "mft_modified": _u64(rec, c_abs + 16),
                            "accessed": _u64(rec, c_abs + 24),
                        }
                    elif attr_type == 0x30 and c_len >= 66:
                        parent_ref = _u64(rec, c_abs) & 0xFFFFFFFFFFFF
                        fn_created = _u64(rec, c_abs + 8)
                        fn_mod = _u64(rec, c_abs + 16)
                        fn_mft_mod = _u64(rec, c_abs + 24)
                        fn_acc = _u64(rec, c_abs + 32)
                        name_len = rec[c_abs + 64]
                        ns = rec[c_abs + 65]
                        name_bytes = rec[c_abs + 66 : c_abs + 66 + name_len * 2]
                        if len(name_bytes) == name_len * 2:
                            fname = name_bytes.decode("utf-16le", errors="replace")
                            fn_candidates.append(
                                {
                                    "name": fname,
                                    "namespace": ns,
                                    "parent_record": parent_ref,
                                    "created": fn_created,
                                    "modified": fn_mod,
                                    "mft_modified": fn_mft_mod,
                                    "accessed": fn_acc,
                                }
                            )
            pos += attr_len

        if not fn_candidates and si_times is None:
            continue

        # Prefer Win32 or POSIX/Win32&DOS namespace over short DOS 8.3 name (ns == 2)
        best_fn = sorted(fn_candidates, key=lambda c: (1 if c["namespace"] == 2 else 0, -len(c["name"])))[0] if fn_candidates else None
        fname = best_fn["name"] if best_fn else f"mft_record_{idx}"

        anomaly_reasons: list[str] = []
        if si_times and best_fn:
            si_c = si_times["created"]
            fn_c = best_fn["created"]
            if si_c > 0 and fn_c > 0:
                if si_c + 10_000_000 < fn_c:  # SI earlier than FN by > 1s
                    anomaly_reasons.append("SI_CREATED_BEFORE_FN_CREATED")
                if (si_c % 10_000_000 == 0) and (fn_c % 10_000_000 != 0):
                    anomaly_reasons.append("SI_NANOSECONDS_ZEROED")
                if si_times["modified"] + 10_000_000 < si_c:
                    anomaly_reasons.append("MODIFIED_BEFORE_CREATED")

        entry = {
            "record_id": idx,
            "in_use": bool(flags & 0x1),
            "is_directory": bool(flags & 0x2),
            "filename": fname,
            "parent_record": best_fn["parent_record"] if best_fn else None,
            "si_created_utc": filetime_to_iso(si_times["created"]) if si_times else None,
            "si_modified_utc": filetime_to_iso(si_times["modified"]) if si_times else None,
            "fn_created_utc": filetime_to_iso(best_fn["created"]) if best_fn else None,
            "fn_modified_utc": filetime_to_iso(best_fn["modified"]) if best_fn else None,
            "timestomped": bool(anomaly_reasons),
            "timestomp_reasons": anomaly_reasons,
        }
        entries.append(entry)
        if anomaly_reasons:
            timestomped.append(entry)

    return {
        "schema": "aether_mft.v1",
        "record_count": len(entries),
        "timestomp_count": len(timestomped),
        "entries": entries,
        "timestomped_entries": timestomped,
    }


def _read_hive_cell(hive_bytes: bytes, rel_off: int) -> bytes | None:
    if rel_off == 0xFFFFFFFF or rel_off == 0:
        return None
    abs_off = 0x1000 + rel_off
    if abs_off + 4 > len(hive_bytes):
        return None
    raw_sz = _i32(hive_bytes, abs_off)
    if raw_sz >= 0:  # unallocated or zero
        return None
    cell_sz = -raw_sz
    if abs_off + cell_sz > len(hive_bytes) or cell_sz < 8:
        return None
    return hive_bytes[abs_off + 4 : abs_off + cell_sz]


def _decode_vk_value(hive_bytes: bytes, vk_cell: bytes) -> dict[str, Any] | None:
    if len(vk_cell) < 20 or vk_cell[:2] != b"vk":
        return None
    name_len = _u16(vk_cell, 2)
    data_sz_raw = _u32(vk_cell, 4)
    data_off = _u32(vk_cell, 8)
    data_type = _u32(vk_cell, 12)
    flags = _u16(vk_cell, 16)

    name_bytes = vk_cell[20 : 20 + name_len]
    if name_len == 0:
        val_name = "(Default)"
    elif flags & 0x1:
        val_name = name_bytes.decode("latin-1", errors="replace")
    else:
        val_name = name_bytes.decode("utf-16le", errors="replace")

    inline = bool(data_sz_raw & 0x80000000)
    real_sz = data_sz_raw & 0x7FFFFFFF
    if inline:
        raw_val = struct.pack("<I", data_off)[: min(real_sz, 4)]
    else:
        cell = _read_hive_cell(hive_bytes, data_off)
        raw_val = (cell or b"")[:real_sz]

    decoded: Any
    if data_type in (1, 2):  # REG_SZ / REG_EXPAND_SZ
        decoded = raw_val.decode("utf-16le", errors="replace").rstrip("\x00")
    elif data_type == 4 and len(raw_val) >= 4:
        decoded = _u32(raw_val, 0)
    elif data_type == 11 and len(raw_val) >= 8:
        decoded = _u64(raw_val, 0)
    else:
        decoded = raw_val[:64].hex()

    return {"name": val_name, "type": data_type, "value": decoded}


def _collect_subkey_offsets(hive_bytes: bytes, list_off: int) -> list[int]:
    cell = _read_hive_cell(hive_bytes, list_off)
    if not cell or len(cell) < 4:
        return []
    sig = cell[:2]
    count = _u16(cell, 2)
    offsets: list[int] = []
    if sig in (b"lf", b"lh"):
        for i in range(count):
            pos = 4 + i * 8
            if pos + 4 <= len(cell):
                offsets.append(_u32(cell, pos))
    elif sig == b"li":
        for i in range(count):
            pos = 4 + i * 4
            if pos + 4 <= len(cell):
                offsets.append(_u32(cell, pos))
    elif sig == b"ri":
        for i in range(count):
            pos = 4 + i * 4
            if pos + 4 <= len(cell):
                offsets.extend(_collect_subkey_offsets(hive_bytes, _u32(cell, pos)))
    return offsets


def parse_registry_hive(hive_bytes: bytes, max_keys: int = 2048) -> dict[str, Any]:
    """Parse a Windows Registry Hive (`regf`) recursively from root cell."""
    if len(hive_bytes) < 0x1020 or hive_bytes[:4] != b"regf":
        return {"schema": "aether_registry.v1", "valid": False, "keys": [], "persistence_hits": []}

    root_rel = _u32(hive_bytes, 0x24)
    keys: list[dict[str, Any]] = []
    persistence_hits: list[dict[str, Any]] = []
    visited: set[int] = set()

    def _walk_nk(rel_off: int, prefix: str) -> None:
        if rel_off in visited or len(keys) >= max_keys:
            return
        visited.add(rel_off)
        cell = _read_hive_cell(hive_bytes, rel_off)
        if not cell or len(cell) < 0x4C or cell[:2] != b"nk":
            return
        flags = _u16(cell, 2)
        last_write = _u64(cell, 4)
        sub_list_off = _u32(cell, 0x1C)
        val_count = _u32(cell, 0x24)
        val_list_off = _u32(cell, 0x28)
        name_len = _u16(cell, 0x48)
        name_bytes = cell[0x4C : 0x4C + name_len]
        if flags & 0x20:  # compressed ASCII
            kname = name_bytes.decode("latin-1", errors="replace")
        else:
            kname = name_bytes.decode("utf-16le", errors="replace")

        full_path = f"{prefix}\\{kname}" if prefix else kname
        values: list[dict[str, Any]] = []
        if val_count > 0 and val_list_off != 0xFFFFFFFF:
            vlist_cell = _read_hive_cell(hive_bytes, val_list_off)
            if vlist_cell:
                for vi in range(min(val_count, len(vlist_cell) // 4)):
                    vk_off = _u32(vlist_cell, vi * 4)
                    vk_cell = _read_hive_cell(hive_bytes, vk_off)
                    if vk_cell:
                        dec = _decode_vk_value(hive_bytes, vk_cell)
                        if dec:
                            values.append(dec)

        rec = {
            "path": full_path,
            "last_write_utc": filetime_to_iso(last_write),
            "values": values,
        }
        keys.append(rec)
        low = full_path.lower()
        if any(tok in low for tok in _PERSISTENCE_KEY_TOKENS) and values:
            persistence_hits.append(rec)

        if sub_list_off != 0xFFFFFFFF:
            for sub_off in _collect_subkey_offsets(hive_bytes, sub_list_off):
                _walk_nk(sub_off, full_path)

    _walk_nk(root_rel, "")
    return {
        "schema": "aether_registry.v1",
        "valid": True,
        "key_count": len(keys),
        "keys": keys,
        "persistence_hits": persistence_hits,
    }


def parse_evtx_events(evtx_bytes: bytes, max_events: int = 4096) -> dict[str, Any]:
    """Parse Windows EVTX (`ElfFile`) chunks and records."""
    if len(evtx_bytes) < 0x1020 or evtx_bytes[:7] != b"ElfFile":
        return {"schema": "aether_evtx.v1", "valid": False, "events": []}

    events: list[dict[str, Any]] = []
    pos = 0x1000
    while pos + 0x200 <= len(evtx_bytes) and len(events) < max_events:
        if evtx_bytes[pos : pos + 7] != b"ElfChnk":
            pos += 0x10000
            continue
        chunk_end = min(pos + 0x10000, len(evtx_bytes))
        rec_pos = pos + 0x200
        while rec_pos + 24 <= chunk_end and len(events) < max_events:
            if evtx_bytes[rec_pos : rec_pos + 4] != b"\x2a\x2a\x00\x00":
                break
            rec_sz = _u32(evtx_bytes, rec_pos + 4)
            if rec_sz < 28 or rec_pos + rec_sz > chunk_end:
                break
            rec_id = _u64(evtx_bytes, rec_pos + 8)
            written_ft = _u64(evtx_bytes, rec_pos + 16)
            payload = evtx_bytes[rec_pos + 24 : rec_pos + rec_sz - 4]

            # Extract UTF-16LE and ASCII tokens/XML snippets from BinXML payload
            utf16_strings = [
                m.group(0).decode("utf-16le", errors="ignore")
                for m in re.finditer(rb"(?:[\x20-\x7e]\x00){3,}", payload)
            ]
            ascii_strings = [
                m.group(0).decode("ascii", errors="ignore")
                for m in re.finditer(rb"[\x20-\x7e]{4,}", payload)
            ]
            event_id = None
            joined = " ".join(utf16_strings + ascii_strings)
            m_eid = re.search(r"<EventID[^>]*>(\d+)</EventID>|EventID\s*[=:]\s*(\d+)", joined)
            if m_eid:
                event_id = int(m_eid.group(1) or m_eid.group(2))
            else:
                # BinXML value token 0x05 followed by 0x06 (Int16) or 0x08 (Int32) inside payload header fallback
                for cand in (4624, 4625, 4688, 7045, 1102):
                    if struct.pack("<H", cand) in payload and any("Security" in s or "System" in s or "Service" in s or "Event" in s for s in utf16_strings + ascii_strings):
                        event_id = cand
                        break

            mitre = _EVENT_MITRE.get(event_id) if event_id is not None else None
            events.append(
                {
                    "record_id": rec_id,
                    "timestamp_utc": filetime_to_iso(written_ft),
                    "event_id": event_id,
                    "mitre_tactic": mitre[0] if mitre else None,
                    "mitre_technique": mitre[1] if mitre else None,
                    "description": mitre[2] if mitre else None,
                    "strings": (utf16_strings + ascii_strings)[:16],
                }
            )
            rec_pos += rec_sz
        pos += 0x10000

    return {
        "schema": "aether_evtx.v1",
        "valid": True,
        "event_count": len(events),
        "events": events,
    }


def parse_prefetch_scca(pf_bytes: bytes) -> dict[str, Any]:
    """Parse uncompressed Windows Prefetch (`SCCA`) metadata."""
    if len(pf_bytes) < 0x80 or pf_bytes[4:8] != b"SCCA":
        return {"schema": "aether_prefetch.v1", "valid": False}
    version = _u32(pf_bytes, 0)
    exe_raw = pf_bytes[16:76]
    exe_name = exe_raw.decode("utf-16le", errors="replace").split("\x00", 1)[0]
    pf_hash = _u32(pf_bytes, 76)
    run_count = None
    last_run_utc = None
    if version >= 23 and len(pf_bytes) >= 0xD8:
        last_run_ft = _u64(pf_bytes, 0x80)
        last_run_utc = filetime_to_iso(last_run_ft)
        run_count = _u32(pf_bytes, 0xD0) if version >= 26 else _u32(pf_bytes, 0x98)
    elif version == 17 and len(pf_bytes) >= 0x94:
        last_run_utc = filetime_to_iso(_u64(pf_bytes, 0x78))
        run_count = _u32(pf_bytes, 0x90)
    return {
        "schema": "aether_prefetch.v1",
        "valid": True,
        "version": version,
        "executable": exe_name,
        "prefetch_hash": hex(pf_hash),
        "run_count": run_count,
        "last_run_utc": last_run_utc,
    }


def analyze_disk_registry_evtx(
    mft_bytes: bytes | None = None,
    registry_hive_bytes: bytes | None = None,
    evtx_bytes: bytes | None = None,
    prefetch_blobs: list[bytes] | None = None,
) -> dict[str, Any]:
    """Run unified read-only Disk/Registry/EVTX/Prefetch forensic analysis."""
    mft_res = parse_mft_records(mft_bytes) if mft_bytes else {"record_count": 0, "timestomp_count": 0, "entries": [], "timestomped_entries": []}
    reg_res = parse_registry_hive(registry_hive_bytes) if registry_hive_bytes else {"valid": False, "key_count": 0, "keys": [], "persistence_hits": []}
    evtx_res = parse_evtx_events(evtx_bytes) if evtx_bytes else {"valid": False, "event_count": 0, "events": []}
    pf_res = [parse_prefetch_scca(b) for b in (prefetch_blobs or [])]
    return {
        "schema": "aether_disk_registry_evtx.v1",
        "mft": mft_res,
        "registry": reg_res,
        "evtx": evtx_res,
        "prefetch": [p for p in pf_res if p.get("valid")],
    }
