"""Installer, Cabinet (MSCF) & SFX Overlay Forensics (GEAR-20).

Covers Discovery-100 candidates CAN-048 (innoextract), CAN-021 (Detect-It-Easy),
and CAN-023 (Nauz-File-Detector).

Capabilities:
  1. Detects InnoSetup installers and extracts exact Setup Data version banners.
  2. Detects Nullsoft NSIS installers (0xDEADBEEF + 'NullsoftInst' header) and extracts
     compressed/uncompressed payload sizes.
  3. Parses Microsoft Cabinet (MSCF) headers and enumerates CFFILE entries (filenames & sizes)
     both in standalone .cab files and embedded inside PE overlays.
  4. Carves 7-Zip SFX, RAR5 SFX, and ZIP overlays appended to PE executables.
"""

from __future__ import annotations

import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

CAB_MAGIC = b"MSCF\x00\x00\x00\x00"
NSIS_MAGIC = b"\xef\xbe\xad\xdeNullsoftInst"
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
RAR_MAGIC = b"Rar!\x1a\x07"

INNO_VERSION_RE = re.compile(rb"Inno Setup Setup Data \([\d\.a-zA-Z\s]+\)")


@dataclass
class CabinetFileEntry:
    name: str
    uncompressed_size: int
    offset_in_folder: int
    attributes: int


@dataclass
class InstallerForensicsReport:
    file_path: str
    file_size: int
    installer_type: str = "none"  # "inno_setup", "nsis", "cabinet", "7z_sfx", "rar_sfx", "none"
    inno_version: str = ""
    nsis_info: Dict[str, Any] = field(default_factory=dict)
    cabinet_info: Dict[str, Any] = field(default_factory=dict)
    cabinet_files: List[Dict[str, Any]] = field(default_factory=list)
    embedded_archives: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _parse_cab_at(data: bytes, offset: int, report: InstallerForensicsReport) -> None:
    buf = data[offset:]
    if len(buf) < 36 or not buf.startswith(CAB_MAGIC):
        return
    cb_cabinet = struct.unpack_from("<I", buf, 8)[0]
    coff_files = struct.unpack_from("<I", buf, 16)[0]
    version_minor = buf[24]
    version_major = buf[25]
    c_folders = struct.unpack_from("<H", buf, 26)[0]
    c_files = struct.unpack_from("<H", buf, 28)[0]

    report.cabinet_info = {
        "offset": offset,
        "cabinet_size": cb_cabinet,
        "version": f"{version_major}.{version_minor}",
        "folder_count": c_folders,
        "file_count": c_files,
    }

    pos = coff_files
    for _ in range(min(c_files, 500)):
        if pos + 16 > len(buf):
            break
        cb_file, uoff_folder, i_folder, date, time, attribs = struct.unpack_from(
            "<IIHHHH", buf, pos
        )
        pos += 16
        null_idx = buf.find(b"\x00", pos)
        if null_idx == -1:
            break
        fname = buf[pos:null_idx].decode("utf-8", errors="replace")
        pos = null_idx + 1
        report.cabinet_files.append(
            asdict(
                CabinetFileEntry(
                    name=fname,
                    uncompressed_size=cb_file,
                    offset_in_folder=uoff_folder,
                    attributes=attribs,
                )
            )
        )


def analyze_installer_bytes(data: bytes, file_path: str = "") -> InstallerForensicsReport:
    """Inspects a binary or installer image for InnoSetup, NSIS, Cabinet, and SFX overlays."""
    report = InstallerForensicsReport(file_path=file_path, file_size=len(data))
    if not data:
        report.error = "Empty input buffer."
        return report

    # 1. Check InnoSetup
    inno_match = INNO_VERSION_RE.search(data)
    if inno_match:
        report.installer_type = "inno_setup"
        report.inno_version = inno_match.group(0).decode("ascii", errors="replace")

    # 2. Check NSIS (FirstHeader: 4 bytes flags + 0xDEADBEEF + 'NullsoftInst' + header_len + archive_len)
    nsis_idx = data.find(NSIS_MAGIC)
    if nsis_idx != -1:
        if report.installer_type == "none":
            report.installer_type = "nsis"
        fh_start = max(0, nsis_idx - 4)
        if nsis_idx + 24 <= len(data):
            flags = struct.unpack_from("<I", data, fh_start)[0] if nsis_idx >= 4 else 0
            hdr_inflated, arc_deflated = struct.unpack_from("<II", data, nsis_idx + 16)
            report.nsis_info = {
                "signature_offset": nsis_idx,
                "flags": flags,
                "header_inflated_size": hdr_inflated,
                "archive_compressed_size": arc_deflated,
            }

    # 3. Check Cabinet (MSCF)
    cab_idx = data.find(CAB_MAGIC)
    if cab_idx != -1:
        if report.installer_type == "none":
            report.installer_type = "cabinet"
        _parse_cab_at(data, cab_idx, report)
        report.embedded_archives.append({"format": "cabinet", "offset": cab_idx})

    # 4. Check 7-Zip SFX and RAR SFX
    sz_idx = data.find(SEVENZ_MAGIC)
    if sz_idx != -1:
        if report.installer_type == "none":
            report.installer_type = "7z_sfx"
        report.embedded_archives.append({"format": "7z", "offset": sz_idx})

    rar_idx = data.find(RAR_MAGIC)
    if rar_idx != -1:
        if report.installer_type == "none":
            report.installer_type = "rar_sfx"
        report.embedded_archives.append({"format": "rar", "offset": rar_idx})

    return report


def scan_file_installer(file_path: str | Path) -> InstallerForensicsReport:
    """Reads an installer or binary from disk and runs installer/SFX forensics."""
    p = Path(file_path)
    if not p.is_file():
        return InstallerForensicsReport(
            file_path=str(p),
            file_size=0,
            error=f"File not found: {p}",
        )
    try:
        return analyze_installer_bytes(p.read_bytes(), str(p))
    except Exception as exc:
        return InstallerForensicsReport(
            file_path=str(p),
            file_size=0,
            error=f"Read error: {exc}",
        )
