"""Pilar 14 (v19.0): VM CFG Handler Lifter, SEH/VEH Unpacker & Complete .NET/IL2CPP/Hermes."""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import keystone
import pytest

from aether_re.cil_decompiler import decompile_dotnet_ecma335
from aether_re.dynamic_unpacker import unpack_pe_in_sandbox
from aether_re.managed_reconstructors import decode_hermes_bytecode, recover_il2cpp_metadata
from aether_re.vm_devirtualizer import devirtualize_vm_bytecode_cfg


def _asm64(asm: str) -> bytes:
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    enc, _ = ks.asm(asm)
    return bytes(enc)


def test_vm_bytecode_cfg_devirtualizer_with_loop_and_branch() -> None:
    # Real multi-block x64 function with conditional branch + loop + indirect jump
    code = _asm64(
        "xor rax, rax; "
        "test rcx, rcx; "
        "jle done; "
        "loop_top: "
        "add rax, rdx; "
        "dec rcx; "
        "jg loop_top; "
        "done: "
        "ret"
    )
    res = devirtualize_vm_bytecode_cfg(
        code,
        fn_name="vm_loop_fn",
        sample_vectors=[(0, 5, 0, 0), (4, 3, 0, 0), (5, 7, 0, 0)],
    )
    assert res["status"] == "cfg_devirtualized"
    assert res["basic_blocks_count"] >= 2
    assert res["loops_detected"] >= 1
    assert "L_blk_" in res["devirtualized_c"]
    assert "goto L_blk_" in res["devirtualized_c"]


def test_dynamic_unpacker_seh_veh_exception_dispatch() -> None:
    # Build minimal PE64 with kernel32!AddVectoredExceptionHandler in IAT + INT3 (0xCC)
    # Handler writes 0xC3 into .text (0x140001000) and jumps to OEP (0x1000)
    pe = bytearray(0x3000)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)
    opt = 0x98
    struct.pack_into("<H", pe, opt, 0x020B)  # PE32+
    struct.pack_into("<I", pe, opt + 16, 0x2000)  # EntryPoint = .pack
    struct.pack_into("<Q", pe, opt + 24, 0x140000000)  # ImageBase
    struct.pack_into("<II", pe, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", pe, opt + 56, 0x3000, 0x200)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<I", pe, opt + 108, 16)  # NumberOfRvaAndSizes
    # DataDirectory[1] (Import) at opt + 120: RVA=0x1100, Size=40
    struct.pack_into("<II", pe, opt + 120, 0x1100, 40)

    # Section 1: .text (at opt + 0xF0 = 0x188)
    s1 = 0x188
    pe[s1 : s1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", pe, s1 + 8, 0x1000, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<I", pe, s1 + 36, 0x60000020)
    # Section 2: .pack
    s2 = s1 + 40
    pe[s2 : s2 + 8] = b".pack\x00\x00\x00"
    struct.pack_into("<IIII", pe, s2 + 8, 0x1000, 0x2000, 0x1000, 0x2000)
    struct.pack_into("<I", pe, s2 + 36, 0xE0000020)

    # Import Directory at 0x1100: ILT=0x1140, Name=0x1160 ("kernel32.dll"), IAT=0x1180
    struct.pack_into("<IIIII", pe, 0x1100, 0x1140, 0, 0, 0x1160, 0x1180)
    struct.pack_into("<QQ", pe, 0x1140, 0x1190, 0)
    pe[0x1160 : 0x116D] = b"kernel32.dll\x00"
    struct.pack_into("<QQ", pe, 0x1180, 0x1190, 0)
    struct.pack_into("<H", pe, 0x1190, 0)
    pe[0x1192 : 0x1192 + 28] = b"AddVectoredExceptionHandler\x00"

    # .pack code at 0x140002000: call AddVectoredExceptionHandler(1, 0x140002040); int3; ret
    # handler at 0x140002040 writes 0xC3 to 0x140001000 and jumps to 0x140001000
    stub_b, _ = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64).asm(
        "sub rsp, 0x28; "
        "mov ecx, 1; "
        "mov rax, 0x140002040; mov rdx, rax; "
        "mov rax, 0x140001180; call qword ptr [rax]; "
        "add rsp, 0x28; "
        "int3; ret",
        0x140002000,
    )
    hdlr_b, _ = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64).asm(
        "mov rax, 0x140001000; mov byte ptr [rax], 0xc3; jmp rax",
        0x140002040,
    )
    pe[0x2000 : 0x2000 + len(stub_b)] = bytes(stub_b)
    pe[0x2040 : 0x2040 + len(hdlr_b)] = bytes(hdlr_b)

    rep = unpack_pe_in_sandbox(bytes(pe))
    assert rep["seh_veh_exceptions_dispatched"] >= 1
    assert rep["oep_detected"] is True
    assert rep["oep_rva"] == "0x1000"


def test_real_dotnet_newarr_switch_field_decompile(tmp_path: Path) -> None:
    dotnet = shutil.which("dotnet")
    if not dotnet:
        pytest.skip(".NET SDK required for real ECMA-335 CIL assembly test")

    proj = tmp_path / "dn_proj"
    proj.mkdir()
    (proj / "dn_proj.csproj").write_text(
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net10.0</TargetFramework>"
        "<OutputType>Library</OutputType></PropertyGroup></Project>\n",
        encoding="utf-8",
    )
    (proj / "Sample.cs").write_text(
        """
namespace AetherSample {
    public class Calc {
        public static int ArrSwitch(int x) {
            int[] arr = new int[4];
            arr[0] = 10;
            arr[1] = 20;
            switch (x) {
                case 0: return arr[0];
                case 1: return arr[1];
                default: return arr.Length;
            }
        }
    }
}
""",
        encoding="utf-8",
    )
    build = subprocess.run([dotnet, "build", "-c", "Release"], cwd=proj, capture_output=True, text=True, timeout=120)
    if build.returncode != 0:
        pytest.skip(f"dotnet build failed: {build.stdout + build.stderr}")
    dll = next((proj / "bin" / "Release").rglob("dn_proj.dll"))
    dec = decompile_dotnet_ecma335(dll.read_bytes(), assembly_name="AetherSample")
    assert dec["status"] == "complete"
    cs_text = "\n".join(dec["cs_files"].values())
    assert "new int[" in cs_text
    assert ".Length" in cs_text


def test_il2cpp_structured_tables_and_hermes_disasm() -> None:
    # 1. IL2CPP metadata with Il2CppTypeDefinition table (stride 88)
    strs = b"\x00PlayerController\x00Game.Core\x00"
    str_off = 256
    type_off = 320
    tdef = bytearray(88)
    struct.pack_into("<II", tdef, 0, 1, 18)  # PlayerController, Game.Core
    il2cpp = bytearray(type_off + 88)
    il2cpp[:4] = b"\xaf\x1b\xb1\xfa"
    struct.pack_into("<i", il2cpp, 4, 29)
    struct.pack_into("<II", il2cpp, 16, str_off, len(strs))
    struct.pack_into("<II", il2cpp, 160, type_off, 88)
    il2cpp[str_off : str_off + len(strs)] = strs
    il2cpp[type_off : type_off + 88] = tdef

    il_rep = recover_il2cpp_metadata(bytes(il2cpp))
    assert il_rep["valid"] is True
    assert il_rep["structured_types"][0] == {"name": "PlayerController", "namespace": "Game.Core"}

    # 2. Hermes .hbc with SmallFunctionHeader (at 128) + LoadConstUInt8, Add, Ret
    bc = bytes([0x5D, 1, 42, 0x2D, 0, 1, 1, 0x52, 0])
    hbc = bytearray(256)
    hbc[:8] = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
    struct.pack_into("<I", hbc, 8, 96)
    struct.pack_into("<I", hbc, 32, len(hbc))
    struct.pack_into("<II", hbc, 40, 1, 0)
    struct.pack_into("<IIII", hbc, 128, 192, 2, len(bc), 0)
    hbc[192 : 192 + len(bc)] = bc

    hbc_rep = decode_hermes_bytecode(bytes(hbc))
    assert hbc_rep["valid"] is True
    insns = hbc_rep["functions_disassembled"][0]["insns"]
    assert any("LoadConstUInt8" in i for i in insns)
    assert any("Add(" in i for i in insns)
    assert any("Ret(" in i for i in insns)
