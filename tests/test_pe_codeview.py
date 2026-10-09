import os
from pathlib import Path
import struct
import uuid

import pytest

from aether_re.pe_debug import parse_pe_codeview


def test_codeview_reader_fails_closed_on_non_pe_bytes():
    report = parse_pe_codeview(b"not-a-pe")
    assert report["status"] == "invalid"
    assert report["code"] == "dos_header_invalid"
    assert report["records"] == []


def _pe_with_rsds_record() -> bytes:
    image = bytearray(0x340)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, 224, 0)

    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 92, 16)
    struct.pack_into("<II", image, optional + 96 + 8 * 6, 0x1000, 28)

    section = optional + 224
    image[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x140, 0x1000, 0x140, 0x200)

    rsds = (
        b"RSDS"
        + uuid.UUID("d7d77f28-5f2e-4d1e-8f26-1d408ba6c58c").bytes_le
        + struct.pack("<I", 1)
        + b"fixture.pdb\0"
    )
    struct.pack_into("<IIHHIIII", image, 0x200, 0, 0x12345678, 0, 0, 2, len(rsds), 0x1040, 0x240)
    image[0x240 : 0x240 + len(rsds)] = rsds
    return bytes(image)


def test_codeview_reader_recovers_rsds_from_bounded_pe_fixture():
    report = parse_pe_codeview(_pe_with_rsds_record())
    assert report["status"] == "complete"
    assert len(report["records"]) == 1
    assert report["records"][0]["kind"] == "RSDS"
    assert report["records"][0]["pdb_name"] == "fixture.pdb"


def test_codeview_reader_recovers_rsds_from_real_msvc_artifact_when_configured():
    fixture = os.environ.get("MEGAZORD_MSVC_PE_FIXTURE")
    if not fixture:
        pytest.skip("MSVC integration fixture ausente; configure MEGAZORD_MSVC_PE_FIXTURE")
    exe = Path(fixture)
    assert exe.is_file(), "MEGAZORD_MSVC_PE_FIXTURE must identify a materialized PE file"
    report = parse_pe_codeview(exe.read_bytes())
    assert report["status"] == "complete"
    assert len(report["records"]) == 1
    assert report["records"][0]["kind"] == "RSDS"
    assert report["records"][0]["pdb_name"].lower().endswith(exe.stem.lower() + ".pdb")

