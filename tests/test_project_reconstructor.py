"""Tests for GEAR-23: Full-Project Compilable Twin Reconstructor & Behavioral Congruence Engine."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from aether_re.project_reconstructor import (
    _MemoryArena,
    _execute_lifted_c_ast,
    compile_reconstructed_project,
    reconstruct_project,
)
try:
    from tests.test_electron_asar_forensics import _build_synthetic_asar
except ModuleNotFoundError:
    import sys as _sys
    _tests_dir = str(Path(__file__).resolve().parent)
    if _tests_dir not in _sys.path:
        _sys.path.insert(0, _tests_dir)
    from test_electron_asar_forensics import _build_synthetic_asar


def _build_synthetic_pe64_with_exports() -> bytes:
    """Builds a minimal valid PE64 DLL with two x86_64 exported functions:
    1. add_mul(rcx, rdx, r8, r9): mov rax, rcx; add rax, rdx; imul rax, r8; ret
    2. xor_shift(rcx, rdx, r8, r9): mov rax, rcx; xor rax, rdx; shl rax, 2; ret
    """
    dos_header = bytearray(0x40)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x40)

    pe_sig = b"PE\x00\x00"
    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # AMD64
        2,       # .text, .edata
        0x65000000,
        0,
        0,
        240,
        0x2022,  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
    )

    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x020B)  # PE32+
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt_header, 20, 0x1000)  # BaseOfCode
    struct.pack_into("<Q", opt_header, 24, 0x180000000)
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)   # FileAlignment
    struct.pack_into("<I", opt_header, 56, 0x3000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x200)   # SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, 2)       # Subsystem GUI
    struct.pack_into("<I", opt_header, 108, 16)     # NumberOfRvaAndSizes
    # DataDirectory[0] = Export Directory at RVA 0x2000, size 0x100
    struct.pack_into("<II", opt_header, 112, 0x2000, 0x100)

    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,  # CODE | EXECUTE | READ
    )
    sec_edata = struct.pack(
        "<8sIIIIIIHHI",
        b".edata\x00\x00",
        0x200,
        0x2000,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        0x40000040,  # INITIALIZED_DATA | READ
    )

    headers = (bytes(dos_header) + pe_sig + coff_header + bytes(opt_header) + sec_text + sec_edata).ljust(
        0x200, b"\x00"
    )

    # .text:
    # 0x1000: add_mul -> mov rax, rcx (48 89 c8); add rax, rdx (48 01 d0); imul rax, r8 (49 0f af c0); ret (c3)
    fn1 = b"\x48\x89\xc8\x48\x01\xd0\x49\x0f\xaf\xc0\xc3"
    # 0x1020: xor_shift -> mov rax, rcx (48 89 c8); xor rax, rdx (48 31 d0); shl rax, 2 (48 c1 e0 02); ret (c3)
    fn2 = b"\x48\x89\xc8\x48\x31\xd0\x48\xc1\xe0\x02\xc3"
    text_sec = bytearray(0x200)
    text_sec[0 : len(fn1)] = fn1
    text_sec[0x20 : 0x20 + len(fn2)] = fn2

    # .edata at RVA 0x2000 (offset 0x400):
    # IMAGE_EXPORT_DIRECTORY (40 bytes):
    # Base=1, NumberOfFunctions=2, NumberOfNames=2,
    # AddressOfFunctions=0x2030, AddressOfNames=0x2040, AddressOfNameOrdinals=0x2050
    edata = bytearray(0x200)
    struct.pack_into(
        "<IIHHIIIIIII",
        edata,
        0,
        0,       # Characteristics
        0,       # TimeDateStamp
        0,       # MajorVersion
        0,       # MinorVersion
        0x2060,  # Name RVA
        1,       # Base
        2,       # NumberOfFunctions
        2,       # NumberOfNames
        0x2030,  # AddressOfFunctions
        0x2040,  # AddressOfNames
        0x2050,  # AddressOfNameOrdinals
    )
    # AddressOfFunctions (2 RVAs)
    struct.pack_into("<II", edata, 0x30, 0x1000, 0x1020)
    # AddressOfNames (2 RVAs)
    struct.pack_into("<II", edata, 0x40, 0x2070, 0x2080)
    # AddressOfNameOrdinals (2 uint16)
    struct.pack_into("<HH", edata, 0x50, 0, 1)
    # Strings
    edata[0x60 : 0x60 + 9] = b"twin.dll\x00"
    edata[0x70 : 0x70 + 8] = b"add_mul\x00"
    edata[0x80 : 0x80 + 10] = b"xor_shift\x00"

    return headers + bytes(text_sec) + bytes(edata)


def test_pe64_compilable_twin_reconstruction_and_100pct_congruence(tmp_path: Path):
    pe_path = tmp_path / "twin.dll"
    pe_path.write_bytes(_build_synthetic_pe64_with_exports())
    out_dir = tmp_path / "reconstructed_c_project"

    report = reconstruct_project(pe_path, out_dir)
    assert report.status == "complete"
    assert report.project_kind == "pe_native_c"
    assert report.total_exports_reconstructed == 2
    assert report.fully_lifted_functions == 2
    assert report.overall_congruence_pct == 100.0

    # Verify full compilable project tree exists
    assert (out_dir / "CMakeLists.txt").is_file()
    assert (out_dir / "include" / "reconstructed_api.h").is_file()
    assert (out_dir / "src" / "reconstructed_project.c").is_file()
    assert (out_dir / "src" / "exports.def").is_file()
    assert (out_dir / "twin_congruence_report.json").is_file()

    c_src = (out_dir / "src" / "reconstructed_project.c").read_text(encoding="utf-8")
    assert "int64_t add_mul(" in c_src
    assert "int64_t xor_shift(" in c_src


def test_electron_asar_full_project_copy_100pct_congruence(tmp_path: Path):
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(_build_synthetic_asar())
    out_dir = tmp_path / "unpacked_electron_app"

    report = reconstruct_project(asar_path, out_dir)
    assert report.status == "complete"
    assert report.project_kind == "electron_asar"
    assert report.total_exports_reconstructed == 3
    assert report.overall_congruence_pct == 100.0
    assert (out_dir / "package.json").is_file()
    assert (out_dir / "main.js").is_file()
    assert (out_dir / "app.jsc").is_file()
    pkg = json.loads((out_dir / "package.json").read_text(encoding="utf-8"))
    assert pkg["name"] == "aether-desktop"


def test_real_cpp_rtti_and_cjson_memory_twin_reconstruction(tmp_path: Path):
    repo_root = Path(__file__).resolve().parent.parent
    poly_dll = repo_root / "external_test_repos" / "cpp_poly" / "poly_test.dll"
    cjson_dll = repo_root / "external_test_repos" / "cjson" / "cjson.dll"
    if not poly_dll.is_file() or not cjson_dll.is_file():
        return

    poly_rep = reconstruct_project(poly_dll, tmp_path / "poly_twin")
    assert poly_rep.status == "complete"
    assert poly_rep.fully_lifted_functions >= 9
    assert poly_rep.overall_congruence_pct == 100.0
    assert any("FastProcessor" in c for c in poly_rep.rtti_classes)
    assert any("CryptoProcessor" in c for c in poly_rep.rtti_classes)
    poly_map = {f["name"]: f for f in poly_rep.functions}
    for req_poly in ("create_processor", "execute_processor", "reset_processor", "destroy_processor"):
        assert poly_map[req_poly]["is_fully_lifted"] is True, req_poly

    poly_fns = {f["name"]: f["lifted_c_code"] for f in poly_rep.functions}
    arena = _MemoryArena()
    arena.write(0x10008, 4, 0)
    arena.write(0x1000C, 4, 3)
    assert _execute_lifted_c_ast(poly_fns["FastProcessor_v0_slot1"], 0x10000, 10, 0, 0, arena) == 31
    assert _execute_lifted_c_ast(poly_fns["FastProcessor_v0_slot1"], 0x10000, 10, 0, 0, arena) == 32

    cjson_rep = reconstruct_project(cjson_dll, tmp_path / "cjson_twin")
    assert cjson_rep.status == "complete"
    assert cjson_rep.total_exports_reconstructed == 78
    assert cjson_rep.fully_lifted_functions == 78
    assert cjson_rep.ctree_structured_functions == 78
    assert cjson_rep.ghidra_enriched_functions == 78
    assert cjson_rep.overall_congruence_pct == 100.0
    assert cjson_rep.struct_layouts_count >= 5
    lifted_map = {f["name"]: f for f in cjson_rep.functions}
    for req_sym in (
        "cJSON_Compare",
        "cJSON_GetErrorPtr",
        "cJSON_InitHooks",
        "cJSON_Parse",
        "cJSON_ParseWithLength",
        "cJSON_ParseWithLengthOpts",
        "cJSON_ParseWithOpts",
        "cJSON_Print",
        "cJSON_PrintBuffered",
        "cJSON_PrintPreallocated",
        "cJSON_PrintUnformatted",
        "cJSON_Version",
        "cJSON_CreateArray",
        "cJSON_CreateNumber",
        "cJSON_CreateIntArray",
        "cJSON_CreateFloatArray",
        "cJSON_CreateString",
        "cJSON_CreateTrue",
        "cJSON_AddTrueToObject",
        "cJSON_GetObjectItemCaseSensitive",
        "cJSON_Delete",
        "cJSON_Duplicate",
        "cJSON_Minify",
        "cJSON_ReplaceItemInArray",
        "cJSON_SetValuestring",
        "cJSON_malloc",
        "cJSON_free",
    ):
        assert lifted_map[req_sym]["is_fully_lifted"] is True, req_sym
    assert lifted_map["cJSON_CreateArray"]["returns_double"] is False
    assert lifted_map["cJSON_CreateNumber"]["takes_double_arg0"] is True

    mp_dll = repo_root / "external_test_repos" / "cpp_poly" / "multi_poly.dll"
    if mp_dll.is_file():
        mp_rep = reconstruct_project(mp_dll, tmp_path / "multi_poly_twin")
        assert mp_rep.status == "complete"
        assert mp_rep.fully_lifted_functions >= 10
        assert mp_rep.overall_congruence_pct == 100.0
        mp_map = {f["name"]: f for f in mp_rep.functions}
        for req_mp in ("create_dual_device", "read_from_device", "write_to_device", "destroy_dual_device"):
            assert mp_map[req_mp]["is_fully_lifted"] is True, req_mp
        build_mp = compile_reconstructed_project(tmp_path / "multi_poly_twin")
        assert build_mp["compiled"] is True

    te_dll = repo_root / "external_test_repos" / "tinyexpr" / "tinyexpr.dll"
    if te_dll.is_file():
        te_rep = reconstruct_project(te_dll, tmp_path / "tinyexpr_twin")
        assert te_rep.status == "complete"
        assert te_rep.fully_lifted_functions >= 2
        assert te_rep.overall_congruence_pct == 100.0
        te_map = {f["name"]: f for f in te_rep.functions}
        assert te_map["te_eval"]["is_fully_lifted"] is True
        assert te_map["te_free"]["is_fully_lifted"] is True
        build_te = compile_reconstructed_project(tmp_path / "tinyexpr_twin")
        assert build_te["compiled"] is True
    structured_c = (tmp_path / "cjson_twin" / "src" / "reconstructed_structured.c").read_text(encoding="utf-8")
    assert "while (1)" in structured_c

    build_poly = compile_reconstructed_project(tmp_path / "poly_twin")
    assert build_poly["compiled"] is True
    assert Path(build_poly["dll_path"]).is_file()

    build_cj = compile_reconstructed_project(tmp_path / "cjson_twin")
    assert build_cj["compiled"] is True
    assert Path(build_cj["dll_path"]).is_file()
