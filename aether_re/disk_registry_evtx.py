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


def _decode_ntfs_data_runs(run_bytes: bytes) -> list[dict[str, int]]:
    """Decode NTFS non-resident `$DATA` (0x80) runlist into (lcn, cluster_count) extents."""
    runs: list[dict[str, int]] = []
    pos = 0
    cur_lcn = 0
    while pos < len(run_bytes):
        hdr = run_bytes[pos]
        if hdr == 0:
            break
        len_sz = hdr & 0x0F
        off_sz = (hdr >> 4) & 0x0F
        pos += 1
        if len_sz == 0 or pos + len_sz + off_sz > len(run_bytes):
            break
        cluster_count = int.from_bytes(run_bytes[pos : pos + len_sz], "little", signed=False)
        pos += len_sz
        if off_sz > 0:
            lcn_delta = int.from_bytes(run_bytes[pos : pos + off_sz], "little", signed=True)
            pos += off_sz
            cur_lcn += lcn_delta
            runs.append({"lcn": cur_lcn, "cluster_count": cluster_count, "sparse": False})
        else:
            runs.append({"lcn": 0, "cluster_count": cluster_count, "sparse": True})
    return runs


def parse_mft_records(mft_bytes: bytes, record_size: int = 1024) -> dict[str, Any]:
    """Parse NTFS `$MFT` records, non-resident `$DATA` runs, and detect `$SI` vs `$FN` timestomping."""
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
        data_runs: list[dict[str, int]] = []
        logical_size: int | None = None

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
                    elif attr_type == 0x80:
                        logical_size = c_len
            elif non_resident == 1 and attr_type == 0x80 and pos + 64 <= len(rec):
                run_off = _u16(rec, pos + 32)
                logical_size = _u64(rec, pos + 48)
                if pos + run_off < pos + attr_len:
                    data_runs.extend(_decode_ntfs_data_runs(bytes(rec[pos + run_off : pos + attr_len])))
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
            "logical_size": logical_size,
            "data_runs": data_runs,
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


def _binxml_read_name(chunk: bytes, name_off: int) -> tuple[str, int]:
    """Read a BinXML Name entry (`next_off:u32, hash:u16, len:u16, utf16le + nul`) from chunk."""
    if name_off < 0 or name_off + 8 > len(chunk):
        return "", name_off
    char_len = _u16(chunk, name_off + 6)
    byte_len = char_len * 2
    end = name_off + 8 + byte_len
    if end > len(chunk):
        return "", end
    name = chunk[name_off + 8 : end].decode("utf-16le", errors="replace")
    return name, end + 2  # trailing NUL UTF-16LE


def _binxml_decode_val(val_type: int, raw: bytes) -> Any:
    vt = val_type & 0x7F
    if not raw:
        return None
    try:
        if vt == 0x01:  # UnicodeString
            return raw.decode("utf-16le", errors="replace").rstrip("\x00")
        if vt == 0x02:  # AnsiString
            return raw.decode("latin-1", errors="replace").rstrip("\x00")
        if vt == 0x03 and len(raw) >= 1:
            return struct.unpack_from("<b", raw, 0)[0]
        if vt == 0x04 and len(raw) >= 1:
            return raw[0]
        if vt == 0x05 and len(raw) >= 2:
            return struct.unpack_from("<h", raw, 0)[0]
        if vt == 0x06 and len(raw) >= 2:
            return struct.unpack_from("<H", raw, 0)[0]
        if vt == 0x07 and len(raw) >= 4:
            return struct.unpack_from("<i", raw, 0)[0]
        if vt == 0x08 and len(raw) >= 4:
            return struct.unpack_from("<I", raw, 0)[0]
        if vt == 0x09 and len(raw) >= 8:
            return struct.unpack_from("<q", raw, 0)[0]
        if vt == 0x0A and len(raw) >= 8:
            return struct.unpack_from("<Q", raw, 0)[0]
        if vt == 0x0D and len(raw) >= 4:
            return bool(struct.unpack_from("<I", raw, 0)[0])
        if vt == 0x0F and len(raw) >= 16:
            import uuid
            return str(uuid.UUID(bytes_le=raw[:16]))
        if vt == 0x11 and len(raw) >= 8:
            return filetime_to_iso(_u64(raw, 0))
        if vt == 0x15 and len(raw) >= 4:
            return hex(_u32(raw, 0))
        if vt == 0x16 and len(raw) >= 8:
            return hex(_u64(raw, 0))
    except Exception:
        pass
    return raw[:32].hex()


def _parse_binxml_template_fields(chunk: bytes, tmpl_start: int, tmpl_end: int) -> dict[int, str]:
    """Map substitution indices inside a BinXML TemplateDefinition to semantic element/attribute tags."""
    sub_map: dict[int, str] = {}
    pos = tmpl_start
    if pos + 4 <= tmpl_end and chunk[pos] == 0x0F:
        pos += 4  # FragmentHeader
    elem_stack: list[str] = []
    cur_attr: str | None = None
    in_attrs = False
    while pos < tmpl_end:
        tok = chunk[pos]
        pos += 1
        if tok == 0x00:  # EOF
            break
        elif tok in (0x01, 0x41):  # OpenStartElement
            if pos + 10 > tmpl_end:
                break
            pos += 6  # dep_id(2) + data_size(4)
            name_off = _u32(chunk, pos)
            pos += 4
            ename, after_inline = _binxml_read_name(chunk, name_off)
            if name_off == pos:
                pos = after_inline
            elem_stack.append(ename)
            cur_attr = None
            if tok == 0x41 and pos + 4 <= tmpl_end:
                pos += 4  # attr_list_size
                in_attrs = True
            else:
                in_attrs = False
        elif tok in (0x06, 0x46):  # Attribute
            if pos + 4 > tmpl_end:
                break
            name_off = _u32(chunk, pos)
            pos += 4
            aname, after_inline = _binxml_read_name(chunk, name_off)
            if name_off == pos:
                pos = after_inline
            cur_attr = aname
        elif tok == 0x02:  # CloseStartElement
            in_attrs = False
            cur_attr = None
        elif tok == 0x03:  # CloseEmptyElement
            in_attrs = False
            cur_attr = None
            if elem_stack:
                elem_stack.pop()
        elif tok == 0x04:  # EndElement
            cur_attr = None
            if elem_stack:
                elem_stack.pop()
        elif tok in (0x05, 0x45):  # ValueText
            if pos + 3 > tmpl_end:
                break
            val_type = chunk[pos]
            pos += 1
            if val_type == 0x01:
                slen = _u16(chunk, pos)
                pos += 2 + slen * 2
            else:
                break
        elif tok in (0x0D, 0x0E):  # NormalSubstitution / OptionalSubstitution
            if pos + 3 > tmpl_end:
                break
            sub_id = _u16(chunk, pos)
            pos += 3  # sub_id(2) + val_type(1)
            parent = elem_stack[-1] if elem_stack else ""
            sub_map[sub_id] = f"{parent}@{cur_attr}" if (in_attrs and cur_attr) else parent
        elif tok == 0x0F and pos + 3 <= tmpl_end:
            pos += 3
        else:
            # Unknown or EntityRef/CharRef token — step safely
            if tok in (0x07, 0x47, 0x08, 0x48):
                pos += 2
            elif tok in (0x09, 0x49):
                pos += 4
    return sub_map


def _decode_binxml_record(chunk: bytes, rel_payload_off: int, rel_payload_end: int, tmpl_cache: dict[int, dict[int, str]]) -> dict[str, Any] | None:
    """Decode a real Windows BinXML EVTX record via TemplateInstance + SubstitutionArray."""
    pos = rel_payload_off
    if pos + 14 > rel_payload_end or chunk[pos] != 0x0F:
        return None
    pos += 4  # FragmentHeader (0x0F 0x01 0x01 0x00)
    if pos >= rel_payload_end or chunk[pos] != 0x0C:
        return None
    pos += 2  # 0x0C + version byte
    _tmpl_id = _u32(chunk, pos)
    tmpl_off = _u32(chunk, pos + 4)
    pos += 8

    # Inline TemplateDefinition sits directly at pos when tmpl_off == pos
    if tmpl_off == pos:
        if pos + 24 > rel_payload_end:
            return None
        tmpl_sz = _u32(chunk, pos + 20)
        tmpl_body_start = pos + 24
        tmpl_body_end = min(len(chunk), tmpl_body_start + tmpl_sz)
        tmpl_cache[tmpl_off] = _parse_binxml_template_fields(chunk, tmpl_body_start, tmpl_body_end)
        pos = tmpl_body_end
    elif tmpl_off not in tmpl_cache and tmpl_off + 24 <= len(chunk):
        tmpl_sz = _u32(chunk, tmpl_off + 20)
        tmpl_cache[tmpl_off] = _parse_binxml_template_fields(chunk, tmpl_off + 24, min(len(chunk), tmpl_off + 24 + tmpl_sz))

    if pos + 4 > rel_payload_end:
        return None
    num_subs = _u32(chunk, pos)
    pos += 4
    if num_subs > 512 or pos + num_subs * 4 > rel_payload_end:
        return None
    descs: list[tuple[int, int]] = []
    for _ in range(num_subs):
        sz, vt = struct.unpack_from("<HB", chunk, pos)
        descs.append((sz, vt))
        pos += 4

    decoded_subs: list[Any] = []
    for sz, vt in descs:
        raw_v = chunk[pos : pos + sz]
        pos += sz
        if (vt & 0x7F) == 0x21 and len(raw_v) >= 14 and raw_v[0] == 0x0F:
            # Nested BinXML fragment (e.g. EventData template!)
            nested_vals: list[str] = []
            for m in re.finditer(rb"(?:[\x20-\x7e]\x00){2,}", raw_v):
                nested_vals.append(m.group(0).decode("utf-16le", errors="ignore"))
            decoded_subs.append(nested_vals[:8])
        else:
            decoded_subs.append(_binxml_decode_val(vt, raw_v))

    field_map = tmpl_cache.get(tmpl_off, {})
    fields: dict[str, Any] = {}
    for idx, val in enumerate(decoded_subs):
        tag = field_map.get(idx)
        if tag and val is not None:
            fields[tag] = val

    eid_raw = fields.get("EventID")
    event_id = int(eid_raw) if isinstance(eid_raw, int) else None
    if event_id is None:
        # Windows System header commonly puts EventID as UInt16 at sub index 3 or first integer in 1..65535
        for idx, (sz, vt) in enumerate(descs):
            if (vt & 0x7F) == 0x06 and isinstance(decoded_subs[idx], int) and 1 <= decoded_subs[idx] <= 65535:
                event_id = decoded_subs[idx]
                break

    return {
        "binxml_decoded": True,
        "event_id": event_id,
        "provider": fields.get("Provider@Name") or (decoded_subs[0] if decoded_subs and isinstance(decoded_subs[0], str) else None),
        "channel": fields.get("Channel"),
        "computer": fields.get("Computer"),
        "fields": {k: v for k, v in fields.items() if not isinstance(v, list) or v},
        "strings": [str(v) for v in decoded_subs if isinstance(v, str) and len(v) >= 2][:16],
    }


def parse_evtx_events(evtx_bytes: bytes, max_events: int = 4096) -> dict[str, Any]:
    """Parse Windows EVTX (`ElfFile`) chunks and records using real BinXML decoding + text fallback."""
    if len(evtx_bytes) < 0x1020 or evtx_bytes[:7] != b"ElfFile":
        return {"schema": "aether_evtx.v1", "valid": False, "events": []}

    events: list[dict[str, Any]] = []
    binxml_count = 0
    pos = 0x1000
    while pos + 0x200 <= len(evtx_bytes) and len(events) < max_events:
        if evtx_bytes[pos : pos + 7] != b"ElfChnk":
            pos += 0x10000
            continue
        chunk_end = min(pos + 0x10000, len(evtx_bytes))
        chunk = evtx_bytes[pos:chunk_end]
        tmpl_cache: dict[int, dict[int, str]] = {}
        rec_rel = 0x200
        while rec_rel + 24 <= len(chunk) and len(events) < max_events:
            if chunk[rec_rel : rec_rel + 4] != b"\x2a\x2a\x00\x00":
                break
            rec_sz = _u32(chunk, rec_rel + 4)
            if rec_sz < 28 or rec_rel + rec_sz > len(chunk):
                break
            rec_id = _u64(chunk, rec_rel + 8)
            written_ft = _u64(chunk, rec_rel + 16)

            bx = _decode_binxml_record(chunk, rec_rel + 24, rec_rel + rec_sz - 4, tmpl_cache)
            if bx is not None:
                binxml_count += 1
                event_id = bx["event_id"]
                strings = bx["strings"]
                provider = bx.get("provider")
                channel = bx.get("channel")
                computer = bx.get("computer")
            else:
                payload = chunk[rec_rel + 24 : rec_rel + rec_sz - 4]
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
                strings = (utf16_strings + ascii_strings)[:16]
                provider = channel = computer = None

            mitre = _EVENT_MITRE.get(event_id) if event_id is not None else None
            events.append(
                {
                    "record_id": rec_id,
                    "timestamp_utc": filetime_to_iso(written_ft),
                    "event_id": event_id,
                    "provider": provider,
                    "channel": channel,
                    "computer": computer,
                    "mitre_tactic": mitre[0] if mitre else None,
                    "mitre_technique": mitre[1] if mitre else None,
                    "description": mitre[2] if mitre else None,
                    "strings": strings,
                }
            )
            rec_rel += rec_sz
        pos += 0x10000

    return {
        "schema": "aether_evtx.v1",
        "valid": True,
        "binxml_decoded_count": binxml_count,
        "event_count": len(events),
        "events": events,
    }


def _decompress_mam_prefetch(pf_bytes: bytes) -> bytes | None:
    """Decompress Windows 10/11 MAM\\x04 Prefetch (LZXPRESS Huffman) via ntdll.RtlDecompressBufferEx."""
    if len(pf_bytes) < 12 or pf_bytes[:4] != b"MAM\x04":
        return None
    uncomp_sz = _u32(pf_bytes, 4)
    if uncomp_sz <= 0 or uncomp_sz > 16 * 1024 * 1024:
        return None
    comp_data = pf_bytes[8:]
    try:
        import ctypes
        ntdll = ctypes.windll.ntdll
        fmt = 4  # COMPRESSION_FORMAT_XPRESS_HUFF
        ws_comp = ctypes.c_ulong(0)
        ws_frag = ctypes.c_ulong(0)
        if ntdll.RtlGetCompressionWorkSpaceSize(fmt, ctypes.byref(ws_comp), ctypes.byref(ws_frag)) != 0:
            return None
        out_buf = ctypes.create_string_buffer(uncomp_sz)
        ws_buf = ctypes.create_string_buffer(max(ws_frag.value, 65536))
        final_sz = ctypes.c_ulong(0)
        status = ntdll.RtlDecompressBufferEx(
            fmt,
            out_buf,
            uncomp_sz,
            comp_data,
            len(comp_data),
            ctypes.byref(final_sz),
            ws_buf,
        )
        if status == 0 and final_sz.value >= 0x80:
            return out_buf.raw[: final_sz.value]
    except Exception:
        return None
    return None


def parse_prefetch_scca(pf_bytes: bytes) -> dict[str, Any]:
    """Parse Windows Prefetch (`SCCA` or Windows 10/11 `MAM\\x04` LZXPRESS-compressed)."""
    was_mam = False
    if pf_bytes[:4] == b"MAM\x04":
        dec = _decompress_mam_prefetch(pf_bytes)
        if dec is None:
            return {"schema": "aether_prefetch.v1", "valid": False, "compressed_mam": True}
        pf_bytes = dec
        was_mam = True
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
        "compressed_mam": was_mam,
        "version": version,
        "executable": exe_name,
        "prefetch_hash": hex(pf_hash),
        "run_count": run_count,
        "last_run_utc": last_run_utc,
    }


_USN_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x80000000: "CLOSE",
}


def parse_usn_journal_j(usn_bytes: bytes, max_records: int = 4096) -> dict[str, Any]:
    """Parse NTFS `$UsnJrnl:$J` (`USN_RECORD_V2` / `V3`) change journal records."""
    records: list[dict[str, Any]] = []
    pos = 0
    while pos + 60 <= len(usn_bytes) and len(records) < max_records:
        rec_len = _u32(usn_bytes, pos)
        if rec_len == 0:
            pos = (pos + 8) & ~7
            if pos == 0:
                pos += 8
            continue
        if rec_len < 60 or pos + rec_len > len(usn_bytes):
            break
        major_ver = _u16(usn_bytes, pos + 4)
        if major_ver == 2:
            mft_ref = _u64(usn_bytes, pos + 8) & 0xFFFFFFFFFFFF
            usn = _u64(usn_bytes, pos + 24)
            ts_ft = _u64(usn_bytes, pos + 32)
            reason = _u32(usn_bytes, pos + 40)
            fn_len = _u16(usn_bytes, pos + 56)
            fn_off = _u16(usn_bytes, pos + 58)
            fname = usn_bytes[pos + fn_off : pos + fn_off + fn_len].decode("utf-16le", errors="replace")
            reasons = [lbl for bit, lbl in _USN_REASONS.items() if reason & bit]
            records.append({
                "usn": usn,
                "mft_record_id": mft_ref,
                "timestamp_utc": filetime_to_iso(ts_ft),
                "reasons": reasons,
                "filename": fname,
            })
        pos += rec_len
    return {"schema": "aether_usn_journal.v1", "record_count": len(records), "records": records}


def parse_shimcache_appcompat(raw_bytes: bytes) -> dict[str, Any]:
    """Parse Windows 10/11 `AppCompatCache` (`10ts`) execution entries from SYSTEM hive."""
    entries: list[dict[str, Any]] = []
    pos = 0
    while True:
        idx = raw_bytes.find(b"10ts", pos)
        if idx == -1 or idx + 14 > len(raw_bytes):
            break
        entry_sz = _u32(raw_bytes, idx + 8)
        path_len = _u16(raw_bytes, idx + 12)
        p_start = idx + 14
        if p_start + path_len + 8 <= len(raw_bytes):
            path_str = raw_bytes[p_start : p_start + path_len].decode("utf-16le", errors="replace").rstrip("\x00")
            lm_ft = _u64(raw_bytes, p_start + path_len)
            entries.append({"path": path_str, "last_modified_utc": filetime_to_iso(lm_ft)})
        pos = idx + max(14, entry_sz + 12)
    return {"schema": "aether_shimcache.v1", "entry_count": len(entries), "entries": entries}


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
