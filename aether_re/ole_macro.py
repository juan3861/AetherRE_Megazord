"""Pure-Python OLE2 / Compound File Binary (MS-CFB) & VBA Macro Forensics (GEAR-14).

Implements:
  1. Offline parsing of Compound File Binary Format (MS-CFB) specification.
  2. Traversal of FAT / MiniFAT chains and directory streams.
  3. Discovery of VBA project storage hierarchy (_VBA_PROJECT, dir, Module streams).
  4. MS-OVBA decompression algorithm for compressed VBA source code.
  5. Static heuristic detection of AutoExec triggers, execution primitives, and suspicious APIs.
"""

from __future__ import annotations

import io
import math
import os
import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Directory entry types (MS-CFB 2.6.1)
STGTY_EMPTY = 0
STGTY_STORAGE = 1
STGTY_STREAM = 2
STGTY_LOCKBYTES = 3
STGTY_PROPERTY = 4
STGTY_ROOT = 5

# AutoExec triggers commonly found in malicious office documents
AUTOEXEC_KEYWORDS = [
    "autoexec",
    "autoopen",
    "document_open",
    "workbook_open",
    "autoexit",
    "autoclose",
    "document_close",
    "workbook_close",
    "app_workbookopen",
    "documentopen",
    "workbookopen",
]

# Suspicious functions, APIs and commands
SUSPICIOUS_PATTERNS = {
    "execution": re.compile(
        r"\b(shell|wscript\.shell|exec|run|createobject\s*\(\s*[\"']wscript\.shell[\"']\s*\)|powershell|cmd\.exe)\b",
        re.IGNORECASE,
    ),
    "code_injection": re.compile(
        r"\b(virtualalloc|virtualallocstate|virtualprotect|rtlmovememory|writeprocessmemory|createremotethread|ntqueueapcthread)\b",
        re.IGNORECASE,
    ),
    "network_download": re.compile(
        r"\b(urldownloadtofile|msxml2\.xmlhttp|winhttp\.winhttprequest|microsoft\.xmlhttp|downloadfile|downloadstring)\b",
        re.IGNORECASE,
    ),
    "file_dropper": re.compile(
        r"\b(scripting\.filesystemobject|savetofile|adodb\.stream|writetext|writebytes|environ\s*\(\s*[\"'](?:temp|appdata|tmp)[\"']\s*\))\b",
        re.IGNORECASE,
    ),
    "base64_payload": re.compile(
        r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    ),
    "hex_payload": re.compile(
        r"\b(?:0x[0-9a-fA-F]{2,8}(?:,\s*)?){8,}\b",
    ),
}


@dataclass
class DirEntry:
    entry_id: int
    name: str
    entry_type: int
    color: int
    left_sibling: int
    right_sibling: int
    child: int
    start_sector: int
    size: int


@dataclass
class OleMacroReport:
    file_path: str
    is_ole: bool
    is_valid_cfb: bool
    sector_size: int = 0
    stream_count: int = 0
    streams: List[str] = field(default_factory=list)
    has_vba: bool = False
    vba_modules: List[str] = field(default_factory=list)
    autoexec_triggers: List[str] = field(default_factory=list)
    suspicious_indicators: Dict[str, List[str]] = field(default_factory=dict)
    extracted_macros: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def decompress_vba_stream(compressed_data: bytes) -> bytes:
    """Decompress a VBA stream compressed using MS-OVBA (2.4.1.3.19)."""
    if not compressed_data:
        return b""

    # Compressed VBA stream must start with byte 0x01 (signature)
    if compressed_data[0] != 0x01:
        # Some streams may omit signature byte or already be plaintext
        return compressed_data

    pos = 1
    decompressed = bytearray()
    data_len = len(compressed_data)

    while pos < data_len:
        if pos + 2 > data_len:
            break

        chunk_header = struct.unpack_from("<H", compressed_data, pos)[0]
        pos += 2

        chunk_size = (chunk_header & 0x0FFF) + 3
        is_compressed = (chunk_header & 0x8000) != 0

        chunk_end = min(pos + chunk_size - 2, data_len)

        if not is_compressed:
            # Uncompressed 4096-byte chunk
            raw_len = min(4096, chunk_end - pos)
            decompressed.extend(compressed_data[pos : pos + raw_len])
            pos = chunk_end
            continue

        # Compressed chunk: unpack token sequences
        chunk_decomp_start = len(decompressed)
        while pos < chunk_end:
            flag_byte = compressed_data[pos]
            pos += 1

            for bit in range(8):
                if pos >= chunk_end:
                    break

                flag = (flag_byte >> bit) & 1
                if flag == 0:
                    # Literal token: 1 byte
                    decompressed.append(compressed_data[pos])
                    pos += 1
                else:
                    # Copy token: 2 bytes
                    if pos + 2 > data_len:
                        pos += 2
                        break
                    token = struct.unpack_from("<H", compressed_data, pos)[0]
                    pos += 2

                    decomp_len = len(decompressed) - chunk_decomp_start
                    # Determine bit width for length and offset
                    bit_count = max(4, int(math.ceil(math.log2(max(decomp_len, 1) + 1))))
                    if bit_count > 12:
                        bit_count = 12

                    length_mask = (1 << (16 - bit_count)) - 1
                    length = (token & length_mask) + 3
                    offset = (token >> (16 - bit_count)) + 1

                    if offset > len(decompressed):
                        # Corrupted or malformed offset
                        continue

                    for _ in range(length):
                        decompressed.append(decompressed[-offset])

    return bytes(decompressed)


class OleCompoundFile:
    """Minimal, pure-Python MS-CFB Compound File reader."""

    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 512 or not data.startswith(CFB_SIGNATURE):
            raise ValueError("Data is not a valid OLE2 / CFB compound file.")

        self.sector_shift = struct.unpack_from("<H", data, 30)[0]
        self.mini_sector_shift = struct.unpack_from("<H", data, 32)[0]
        self.sector_size = 1 << self.sector_shift
        self.mini_sector_size = 1 << self.mini_sector_shift

        self.fat_count = struct.unpack_from("<I", data, 44)[0]
        self.first_dir_sector = struct.unpack_from("<I", data, 48)[0]
        self.mini_cutoff = struct.unpack_from("<I", data, 56)[0]
        self.first_minifat_sector = struct.unpack_from("<I", data, 60)[0]
        self.minifat_count = struct.unpack_from("<I", data, 64)[0]
        self.first_difat_sector = struct.unpack_from("<I", data, 68)[0]
        self.difat_count = struct.unpack_from("<I", data, 72)[0]

        self.fat: List[int] = []
        self.minifat: List[int] = []
        self.entries: List[DirEntry] = []
        self.mini_stream: bytes = b""

        self._read_fat()
        self._read_minifat()
        self._read_directory()

        if self.entries and self.entries[0].entry_type == STGTY_ROOT:
            self.mini_stream = self._read_stream_sectors(
                self.entries[0].start_sector, self.entries[0].size, is_mini=False
            )

    def _get_sector_offset(self, sector_id: int) -> int:
        return (sector_id + 1) * self.sector_size

    def _read_fat(self) -> None:
        # Read the first 109 DIFAT entries from the header
        difat = list(struct.unpack_from("<109I", self.data, 76))
        # Remove trailing unallocated DIFAT entries (0xFFFFFFFF or 0xFFFFFFFE)
        difat_sectors = [s for s in difat if s < 0xFFFFFFFC]

        # Read chaining DIFAT sectors if any
        current_difat = self.first_difat_sector
        while current_difat < 0xFFFFFFFC and len(difat_sectors) < self.fat_count:
            offset = self._get_sector_offset(current_difat)
            if offset + self.sector_size > len(self.data):
                break
            num_entries = (self.sector_size // 4) - 1
            entries = struct.unpack_from(f"<{num_entries}I", self.data, offset)
            difat_sectors.extend([s for s in entries if s < 0xFFFFFFFC])
            current_difat = struct.unpack_from("<I", self.data, offset + num_entries * 4)[0]

        # Read the FAT tables
        fat_entries_per_sector = self.sector_size // 4
        for sector_id in difat_sectors[: self.fat_count]:
            offset = self._get_sector_offset(sector_id)
            if offset + self.sector_size <= len(self.data):
                entries = struct.unpack_from(f"<{fat_entries_per_sector}I", self.data, offset)
                self.fat.extend(entries)

    def _read_minifat(self) -> None:
        if self.first_minifat_sector >= 0xFFFFFFFC:
            return
        curr = self.first_minifat_sector
        fat_entries_per_sector = self.sector_size // 4
        visited = set()
        while curr < 0xFFFFFFFC and curr < len(self.fat) and curr not in visited:
            visited.add(curr)
            offset = self._get_sector_offset(curr)
            if offset + self.sector_size <= len(self.data):
                entries = struct.unpack_from(f"<{fat_entries_per_sector}I", self.data, offset)
                self.minifat.extend(entries)
            curr = self.fat[curr]

    def _read_stream_sectors(self, start_sector: int, size: int, is_mini: bool = False) -> bytes:
        if start_sector >= 0xFFFFFFFC:
            return b""
        res = bytearray()
        curr = start_sector
        visited = set()

        if is_mini:
            # Read from Mini Stream using MiniFAT
            while curr < 0xFFFFFFFC and curr < len(self.minifat) and curr not in visited:
                visited.add(curr)
                offset = curr * self.mini_sector_size
                if offset + self.mini_sector_size <= len(self.mini_stream):
                    res.extend(self.mini_stream[offset : offset + self.mini_sector_size])
                curr = self.minifat[curr]
                if len(res) >= size:
                    break
        else:
            # Read from regular sectors using FAT
            while curr < 0xFFFFFFFC and curr < len(self.fat) and curr not in visited:
                visited.add(curr)
                offset = self._get_sector_offset(curr)
                if offset + self.sector_size <= len(self.data):
                    res.extend(self.data[offset : offset + self.sector_size])
                curr = self.fat[curr]
                if len(res) >= size:
                    break

        return bytes(res[:size])

    def _read_directory(self) -> None:
        dir_bytes = self._read_stream_sectors(self.first_dir_sector, 1024 * 1024, is_mini=False)
        entry_size = 128
        total_entries = len(dir_bytes) // entry_size

        for i in range(total_entries):
            offset = i * entry_size
            entry_raw = dir_bytes[offset : offset + entry_size]
            if len(entry_raw) < entry_size:
                break

            name_raw = entry_raw[:64]
            name_len = struct.unpack_from("<H", entry_raw, 64)[0]
            entry_type = entry_raw[66]
            color = entry_raw[67]
            left_sib = struct.unpack_from("<i", entry_raw, 68)[0]
            right_sib = struct.unpack_from("<i", entry_raw, 72)[0]
            child = struct.unpack_from("<i", entry_raw, 76)[0]
            start_sec = struct.unpack_from("<I", entry_raw, 116)[0]
            size = struct.unpack_from("<Q", entry_raw, 120)[0]

            name = ""
            if name_len > 2:
                try:
                    name = name_raw[: name_len - 2].decode("utf-16le", errors="ignore")
                except Exception:
                    name = f"Entry_{i}"

            self.entries.append(
                DirEntry(
                    entry_id=i,
                    name=name,
                    entry_type=entry_type,
                    color=color,
                    left_sibling=left_sib,
                    right_sibling=right_sib,
                    child=child,
                    start_sector=start_sec,
                    size=size,
                )
            )

    def get_stream_data(self, entry: DirEntry) -> bytes:
        if entry.entry_type not in (STGTY_STREAM, STGTY_ROOT):
            return b""
        is_mini = entry.size < self.mini_cutoff and entry.entry_type != STGTY_ROOT
        return self._read_stream_sectors(entry.start_sector, entry.size, is_mini=is_mini)


def scan_ole_vba(data: bytes, file_path: str = "") -> OleMacroReport:
    """Scans and extracts VBA macros from an OLE2 / CFB compound binary."""
    report = OleMacroReport(
        file_path=file_path,
        is_ole=data.startswith(CFB_SIGNATURE),
        is_valid_cfb=False,
    )

    if not report.is_ole:
        report.error = "File does not match OLE2 Compound Document header."
        return report

    try:
        cfb = OleCompoundFile(data)
        report.is_valid_cfb = True
        report.sector_size = cfb.sector_size
    except Exception as exc:
        report.error = f"CFB parsing error: {exc}"
        return report

    vba_entries: List[DirEntry] = []

    for entry in cfb.entries:
        if entry.entry_type in (STGTY_STREAM, STGTY_STORAGE) and entry.name:
            report.streams.append(entry.name)
            name_lower = entry.name.lower()
            if "vba" in name_lower or entry.name in ("dir", "_VBA_PROJECT", "PROJECT"):
                report.has_vba = True
            if entry.entry_type == STGTY_STREAM and entry.size > 0:
                # Potential VBA code module stream
                if not entry.name.startswith(("\x01", "\x03", "\x05")):
                    vba_entries.append(entry)

    report.stream_count = len(report.streams)

    # Extract streams and check for VBA compressed data
    for entry in vba_entries:
        try:
            stream_data = cfb.get_stream_data(entry)
            if not stream_data:
                continue

            # Look for VBA module text offset or try direct decompression
            # In VBA streams, text often starts after an Attribut header or offset specified in dir stream
            extracted_text = ""

            # MS-OVBA decompression attempt
            decompressed = decompress_vba_stream(stream_data)
            if decompressed:
                try:
                    text_candidate = decompressed.decode("latin1", errors="replace")
                    if "Sub " in text_candidate or "Function " in text_candidate or "Attribute " in text_candidate:
                        extracted_text = text_candidate
                except Exception:
                    pass

            if not extracted_text:
                # Fallback: scan for plaintext VBA lines
                try:
                    raw_text = stream_data.decode("latin1", errors="replace")
                    if "Sub " in raw_text or "Function " in raw_text or "Attribute " in raw_text:
                        extracted_text = raw_text
                except Exception:
                    pass

            if extracted_text:
                report.has_vba = True
                report.vba_modules.append(entry.name)
                report.extracted_macros[entry.name] = extracted_text

                # Scan for AutoExec triggers
                text_lower = extracted_text.lower()
                for trigger in AUTOEXEC_KEYWORDS:
                    if trigger in text_lower and trigger not in report.autoexec_triggers:
                        report.autoexec_triggers.append(trigger)

                # Scan for suspicious API patterns
                for cat, pattern in SUSPICIOUS_PATTERNS.items():
                    matches = pattern.findall(extracted_text)
                    if matches:
                        existing = report.suspicious_indicators.setdefault(cat, [])
                        for m in matches:
                            s = m.strip()
                            if s and s not in existing:
                                existing.append(s[:120])
        except Exception:
            continue

    return report


def scan_file_ole_macro(file_path: str | Path) -> OleMacroReport:
    """Reads a file and executes OLE macro audit."""
    p = Path(file_path)
    if not p.is_file():
        return OleMacroReport(
            file_path=str(p),
            is_ole=False,
            is_valid_cfb=False,
            error=f"File not found: {p}",
        )
    try:
        data = p.read_bytes()
        return scan_ole_vba(data, str(p))
    except Exception as exc:
        return OleMacroReport(
            file_path=str(p),
            is_ole=False,
            is_valid_cfb=False,
            error=f"Error reading file: {exc}",
        )
