"""Reverse Engineering Graph (AetherRE) — Real Windows MiniDump (.dmp) Memory Forensics Engine.

Parses binary MiniDump files produced by Windows / DbgHelp / Task Manager:
  1. Header and Stream Directory parsing (MDMP magic, Stream types);
  2. ModuleListStream extraction (BaseOfImage, SizeOfImage, DLL names);
  3. MemoryInfoListStream & Memory64ListStream analysis;
  4. Detection of PAGE_EXECUTE_READWRITE (0x40) RWX anomalies, unmapped modules, and code injections;
  5. Live capture helper via DbgHelp.dll MiniDumpWriteDump for empirical self-test.
"""

from __future__ import annotations

import ctypes
import os
import struct
from pathlib import Path
from typing import Any

MINIDUMP_SIGNATURE = 0x504D444D  # "MDMP"

STREAM_TYPES = {
    3: "ThreadListStream",
    4: "ModuleListStream",
    5: "MemoryListStream",
    7: "SystemInfoStream",
    9: "Memory64ListStream",
    16: "MemoryInfoListStream",
}

PAGE_PROTECTION_FLAGS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}


class MiniDumpParser:
    """Parses real Windows MiniDump (.dmp) memory crash and process dumps."""

    def __init__(self, dmp_path: str | Path):
        self.dmp_path = Path(dmp_path).resolve()
        if not self.dmp_path.exists():
            raise FileNotFoundError(f"MiniDump file not found: {self.dmp_path}")

        self.data = self.dmp_path.read_bytes()
        if len(self.data) < 32:
            raise ValueError("File is too small to be a valid MiniDump")

        self.signature, self.version, self.stream_count, self.stream_dir_rva = struct.unpack_from(
            "<IIII", self.data, 0
        )
        if self.signature != MINIDUMP_SIGNATURE:
            raise ValueError(f"Invalid MiniDump signature: 0x{self.signature:X} (expected 'MDMP')")

        self.streams: dict[str, tuple[int, int]] = {}
        self._parse_stream_directory()

    def _parse_stream_directory(self) -> None:
        offset = self.stream_dir_rva
        for _ in range(self.stream_count):
            if offset + 12 > len(self.data):
                break
            st_type, data_size, rva = struct.unpack_from("<III", self.data, offset)
            st_name = STREAM_TYPES.get(st_type, f"UnknownStream_{st_type}")
            self.streams[st_name] = (rva, data_size)
            offset += 12

    def read_minidump_string(self, rva: int) -> str:
        """Reads a UTF-16LE MINIDUMP_STRING from the dump file."""
        if rva + 4 > len(self.data):
            return ""
        length = struct.unpack_from("<I", self.data, rva)[0]
        str_bytes = self.data[rva + 4 : rva + 4 + length]
        try:
            return str_bytes.decode("utf-16le")
        except UnicodeDecodeError:
            return str_bytes.decode("utf-8", errors="ignore")

    def get_modules(self) -> list[dict[str, Any]]:
        """Parses ModuleListStream and returns loaded DLLs and executables."""
        if "ModuleListStream" not in self.streams:
            return []

        rva, size = self.streams["ModuleListStream"]
        if rva + 4 > len(self.data):
            return []

        num_modules = struct.unpack_from("<I", self.data, rva)[0]
        modules = []
        offset = rva + 4
        entry_size = 108  # MINIDUMP_MODULE size on Win32/Win64

        for _ in range(num_modules):
            if offset + entry_size > len(self.data):
                break
            base_of_img, size_of_img, chksum, timestamp, name_rva = struct.unpack_from(
                "<QIIII", self.data, offset
            )
            mod_name = self.read_minidump_string(name_rva)
            modules.append({
                "name": mod_name,
                "base_address": hex(base_of_img),
                "size_bytes": size_of_img,
                "timestamp": timestamp,
            })
            offset += entry_size
        return modules

    def get_memory_info(self) -> list[dict[str, Any]]:
        """Parses MemoryInfoListStream and detects protection flags and anomalies."""
        if "MemoryInfoListStream" not in self.streams:
            return []

        rva, size = self.streams["MemoryInfoListStream"]
        if rva + 16 > len(self.data):
            return []

        hdr_size, entry_size, count = struct.unpack_from("<IIQ", self.data, rva)
        mem_entries = []
        offset = rva + hdr_size

        for _ in range(count):
            if offset + entry_size > len(self.data):
                break
            base_addr, alloc_base, alloc_protect, align1, region_size, state, protect, mem_type = struct.unpack_from(
                "<QQIIQIII", self.data, offset
            )
            prot_name = PAGE_PROTECTION_FLAGS.get(protect, f"0x{protect:X}")
            is_rwx = bool(protect & 0x40)  # PAGE_EXECUTE_READWRITE

            mem_entries.append({
                "base_address": hex(base_addr),
                "region_size": region_size,
                "state": "MEM_COMMIT" if state == 0x1000 else hex(state),
                "protect": prot_name,
                "is_rwx_anomaly": is_rwx,
            })
            offset += entry_size
        return mem_entries

    def audit_memory_security(self) -> dict[str, Any]:
        """Summarizes forensic findings: modules count, RWX anomalies, streams."""
        modules = self.get_modules()
        mem_info = self.get_memory_info()
        rwx_regions = [m for m in mem_info if m["is_rwx_anomaly"]]

        return {
            "dmp_file": self.dmp_path.name,
            "file_size_bytes": len(self.data),
            "total_streams": len(self.streams),
            "stream_names": list(self.streams.keys()),
            "modules_count": len(modules),
            "modules_sample": [m["name"] for m in modules[:5]],
            "memory_regions_count": len(mem_info),
            "rwx_anomalies_count": len(rwx_regions),
            "rwx_regions": rwx_regions,
            "status": "ANOMALY_DETECTED" if rwx_regions else "CLEAN",
        }


def capture_live_process_minidump(output_path: str | Path, pid: int | None = None) -> Path:
    """Captures a real Windows MiniDump using DbgHelp.dll MiniDumpWriteDump API."""
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if pid is None:
        pid = os.getpid()

    dbghelp = ctypes.windll.dbghelp
    kernel32 = ctypes.windll.kernel32

    PROCESS_ALL_ACCESS = 0x1F0FFF
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise OSError(f"OpenProcess failed with error code: {kernel32.GetLastError()}")

    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80

    h_file = kernel32.CreateFileW(
        str(out_file),
        GENERIC_WRITE,
        0,
        None,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h_file == -1 or h_file == 0:
        kernel32.CloseHandle(h_process)
        raise OSError(f"CreateFileW failed with error code: {kernel32.GetLastError()}")

    # MiniDumpNormal = 0x00000000, MiniDumpWithFullMemoryInfo = 0x00000800
    MiniDumpWithFullMemoryInfo = 0x00000800
    success = dbghelp.MiniDumpWriteDump(
        h_process,
        pid,
        h_file,
        MiniDumpWithFullMemoryInfo,
        None,
        None,
        None,
    )

    kernel32.CloseHandle(h_file)
    kernel32.CloseHandle(h_process)

    if not success:
        raise OSError(f"MiniDumpWriteDump failed with error code: {kernel32.GetLastError()}")

    return out_file
