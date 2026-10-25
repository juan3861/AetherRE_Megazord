"""
AetherRE SOTA Golang Stripped Symbol & pclntab Recovery Engine (GoReSym)
=======================================================================
Extracts symbol tables, function names, entry points, package structures,
and metadata from stripped Go binaries (PE, ELF, Mach-O, Raw) by parsing
the runtime.pclntab (PC-Line Table) across Go versions 1.2 through 1.23+.
"""

from __future__ import annotations

import struct
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# Known pclntab Magic Headers
GO_PCLNTAB_MAGICS = {
    0xFFFFFFFB: "Go 1.2 - 1.15",
    0xFFFFFFF0: "Go 1.16 - 1.17",
    0xFFFFFFFA: "Go 1.18 - 1.19",
    0xFFFFFFF1: "Go 1.20 - 1.23+",
}


@dataclass
class GolangFunction:
    name: str
    entry_pc: int
    package: str
    hex_pc: str


@dataclass
class GolangRecoveryReport:
    is_go_binary: bool
    go_version: Optional[str]
    magic: Optional[str]
    ptr_size: int
    pclntab_offset: Optional[int]
    total_functions: int
    packages: List[str]
    functions: List[Dict[str, Any]]
    elapsed_seconds: float
    error_message: Optional[str] = None


class GolangRecoverEngine:
    """Industrial parser and extractor for Golang runtime pclntab symbol tables."""

    def __init__(self, data: bytes, base_addr: int = 0x00400000):
        self.data = data
        self.base_addr = base_addr

    def _find_pclntab_magic(self) -> List[Tuple[int, int]]:
        """Scans the binary buffer for all known pclntab magic headers."""
        matches: List[Tuple[int, int]] = []
        for magic in GO_PCLNTAB_MAGICS.keys():
            magic_bytes = struct.pack("<I", magic)
            start = 0
            while True:
                idx = self.data.find(magic_bytes, start)
                if idx == -1:
                    break
                # Validate sanity of basic header fields (min_lc and ptr_size)
                if idx + 8 <= len(self.data):
                    min_lc = self.data[idx + 6]
                    ptr_size = self.data[idx + 7]
                    if min_lc in (1, 2, 4) and ptr_size in (4, 8):
                        matches.append((idx, magic))
                start = idx + 4
        return matches

    def recover(self, max_functions: int = 50000) -> GolangRecoveryReport:
        """Parses the pclntab and reconstructs all function symbols and packages."""
        start_time = time.time()
        magic_matches = self._find_pclntab_magic()

        if not magic_matches:
            elapsed = time.time() - start_time
            return GolangRecoveryReport(
                is_go_binary=False,
                go_version=None,
                magic=None,
                ptr_size=0,
                pclntab_offset=None,
                total_functions=0,
                packages=[],
                functions=[],
                elapsed_seconds=round(elapsed, 4),
            )

        # Process first valid candidate
        best_report: Optional[GolangRecoveryReport] = None

        for offset, magic in magic_matches:
            version_str = GO_PCLNTAB_MAGICS.get(magic, "Unknown Go Version")
            try:
                min_lc = self.data[offset + 6]
                ptr_size = self.data[offset + 7]
                ptr_char = "Q" if ptr_size == 8 else "I"
                fmt_ptr = f"<{ptr_char}"
                fmt_2ptr = f"<2{ptr_char}"
                fmt_7ptr = f"<7{ptr_char}"
                fmt_8ptr = f"<8{ptr_char}"
                ptr_bytes = ptr_size

                funcs: List[GolangFunction] = []

                if magic == 0xFFFFFFFB:
                    # Go 1.2 - 1.15
                    nfunc = struct.unpack_from(fmt_ptr, self.data, offset + 8)[0]
                    if nfunc <= 0 or nfunc > max_functions:
                        continue
                    functab_start = offset + 8 + ptr_bytes

                    for i in range(min(nfunc, max_functions)):
                        entry_idx = functab_start + i * (2 * ptr_bytes)
                        if entry_idx + 2 * ptr_bytes > len(self.data):
                            break
                        pc, s_off = struct.unpack_from(fmt_2ptr, self.data, entry_idx)
                        func_struct_idx = offset + s_off
                        if func_struct_idx + ptr_bytes + 4 > len(self.data):
                            continue
                        name_off = struct.unpack_from("<i", self.data, func_struct_idx + ptr_bytes)[0]
                        name_idx = offset + name_off
                        if 0 <= name_idx < len(self.data):
                            end = self.data.find(b"\x00", name_idx)
                            if end != -1 and end - name_idx < 512:
                                name = self.data[name_idx:end].decode("utf-8", errors="ignore")
                                pkg = name.split(".")[0] if "." in name else "main"
                                funcs.append(GolangFunction(name=name, entry_pc=pc, package=pkg, hex_pc=hex(pc)))

                elif magic == 0xFFFFFFF0:
                    # Go 1.16 - 1.17
                    fields = struct.unpack_from(fmt_7ptr, self.data, offset + 8)
                    nfunc = fields[0]
                    funcname_offset = offset + fields[2]
                    functab_offset = offset + fields[6]

                    if nfunc <= 0 or nfunc > max_functions:
                        continue

                    for i in range(min(nfunc, max_functions)):
                        entry_idx = functab_offset + i * (2 * ptr_bytes)
                        if entry_idx + 2 * ptr_bytes > len(self.data):
                            break
                        pc, s_off = struct.unpack_from(fmt_2ptr, self.data, entry_idx)
                        func_struct_idx = offset + s_off
                        if func_struct_idx + ptr_bytes + 4 > len(self.data):
                            continue
                        name_off = struct.unpack_from("<i", self.data, func_struct_idx + ptr_bytes)[0]
                        name_idx = funcname_offset + name_off
                        if 0 <= name_idx < len(self.data):
                            end = self.data.find(b"\x00", name_idx)
                            if end != -1 and end - name_idx < 512:
                                name = self.data[name_idx:end].decode("utf-8", errors="ignore")
                                pkg = name.split(".")[0] if "." in name else "main"
                                funcs.append(GolangFunction(name=name, entry_pc=pc, package=pkg, hex_pc=hex(pc)))

                elif magic in (0xFFFFFFFA, 0xFFFFFFF1):
                    # Go 1.18 - 1.23+
                    fields = struct.unpack_from(fmt_8ptr, self.data, offset + 8)
                    nfunc = fields[0]
                    text_start = fields[2]
                    funcname_offset = offset + fields[3]
                    functab_offset = offset + fields[7]

                    if nfunc <= 0 or nfunc > max_functions:
                        continue

                    # In Go 1.18+, functab stores uint32 entry offsets relative to text_start
                    for i in range(min(nfunc, max_functions)):
                        entry_idx = functab_offset + i * 8
                        if entry_idx + 8 > len(self.data):
                            break
                        entry_off, s_off = struct.unpack_from("<II", self.data, entry_idx)
                        pc = text_start + entry_off
                        func_struct_idx = offset + s_off
                        if func_struct_idx + 8 > len(self.data):
                            continue
                        name_off = struct.unpack_from("<i", self.data, func_struct_idx + 4)[0]
                        name_idx = funcname_offset + name_off
                        if 0 <= name_idx < len(self.data):
                            end = self.data.find(b"\x00", name_idx)
                            if end != -1 and end - name_idx < 512:
                                name = self.data[name_idx:end].decode("utf-8", errors="ignore")
                                pkg = name.split(".")[0] if "." in name else "main"
                                funcs.append(GolangFunction(name=name, entry_pc=pc, package=pkg, hex_pc=hex(pc)))

                if funcs:
                    elapsed = time.time() - start_time
                    pkgs = sorted(list({f.package for f in funcs}))
                    return GolangRecoveryReport(
                        is_go_binary=True,
                        go_version=version_str,
                        magic=hex(magic),
                        ptr_size=ptr_size,
                        pclntab_offset=offset,
                        total_functions=len(funcs),
                        packages=pkgs,
                        functions=[asdict(f) for f in funcs],
                        elapsed_seconds=round(elapsed, 4),
                    )

            except Exception as exc:
                continue

        elapsed = time.time() - start_time
        return GolangRecoveryReport(
            is_go_binary=True,
            go_version=None,
            magic=hex(magic_matches[0][1]),
            ptr_size=0,
            pclntab_offset=magic_matches[0][0],
            total_functions=0,
            packages=[],
            functions=[],
            elapsed_seconds=round(elapsed, 4),
            error_message="Could not traverse function table entries.",
        )


def recover_golang_symbols_from_file(file_path: str | Path) -> Dict[str, Any]:
    """Analyzes a binary file on disk and returns the reconstructed Golang symbols report."""
    p = Path(file_path).resolve()
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Binary file not found: {p}")

    data = p.read_bytes()
    engine = GolangRecoverEngine(data)
    report = engine.recover()
    res = asdict(report)
    res["target"] = str(p)
    res["file_size_bytes"] = len(data)
    return res
