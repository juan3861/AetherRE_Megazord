"""Pilar 4 (v10.5) Empirical Tests: Pure-Python ECMA-335 CIL, APK AXML+JNI, WASM call_indirect+f64, JS SourceMap+HBC & Go/Rust."""
from __future__ import annotations

import base64
import ctypes
import io
import json
import struct
import subprocess
import zipfile
from pathlib import Path

from aether_re.cil_decompiler import decompile_dotnet_ecma335
from aether_re.golang_recover import reconstruct_go_project
from aether_re.managed_reconstructors import decode_axml_binary, reconstruct_dex_apk_project, reconstruct_js_bundle_project, reconstruct_wasm_project
from aether_re.runtime_emitter import _find_msvc_x64_toolchain
from aether_re.rust_recover import reconstruct_rust_project


def _uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _wasm_sec(sec_id: int, payload: bytes) -> bytes:
    return bytes([sec_id]) + _uleb(len(payload)) + payload


def test_v105_pure_python_ecma335_cil_decompiler() -> None:
    # Build synthetic valid PE32+ image containing ECMA-335 BSJB streams (#~, #Strings, #US, #Blob) + Tiny CIL body
    pe = bytearray(0x1000)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    opt = 0x98
    struct.pack_into("<H", pe, opt, 0x020B)
    struct.pack_into("<II", pe, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", pe, opt + 56, 0x2000, 0x200)
    s0 = opt + 0xF0
    pe[s0 : s0 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", pe, s0 + 8, 0xE00, 0x1000, 0xE00, 0x200, 0, 0, 0, 0, 0x60000020)

    # IL method at file 0x200 -> RVA 0x1000: ldarg.0 (0x02), ldarg.1 (0x03), add (0x58), ldc.i4.5 (0x1B), xor (0x61), ret (0x2A) => 6 bytes Tiny (hdr = (6<<2)|2 = 0x1A)
    pe[0x200 : 0x207] = bytes([0x1A, 0x02, 0x03, 0x58, 0x1B, 0x61, 0x2A])

    # Build heaps
    strings = b"\x00CoreAsm.dll\x00CipherBox\x00MyNs\x00MixKeys\x00"
    off_mod = strings.index(b"CoreAsm.dll")
    off_cls = strings.index(b"CipherBox")
    off_ns = strings.index(b"MyNs")
    off_mth = strings.index(b"MixKeys")

    # Blob sig idx=1: len=5, cc=0x00 (static/default), param_cnt=2, ret=I4(0x08), p0=I4(0x08), p1=I4(0x08)
    blob_heap = b"\x00\x05\x00\x02\x08\x08\x08"
    us_heap = b"\x00"

    # #~ header: Module(0), TypeDef(2), MethodDef(6) valid mask = (1<<0)|(1<<2)|(1<<6)
    valid_mask = (1 << 0) | (1 << 2) | (1 << 6)
    tbl = bytearray()
    tbl += struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0)
    tbl += struct.pack("<III", 1, 1, 1)  # counts: 1 Module, 1 TypeDef, 1 MethodDef
    # Module row (2+2+2+2+2 = 10 bytes)
    tbl += struct.pack("<HHHHH", 0, off_mod, 0, 0, 0)
    # TypeDef row (4+2+2+2+2+2 = 14 bytes): flags=0x1, name=off_cls, ns=off_ns, ext=0, field=1, method=1
    tbl += struct.pack("<IHHHHH", 1, off_cls, off_ns, 0, 1, 1)
    # MethodDef row (4+2+2+2+2+2 = 14 bytes): rva=0x1000, impl=0, flags=0x10(Static), name=off_mth, sig=1, param=1
    tbl += struct.pack("<IHHHHH", 0x1000, 0, 0x0010, off_mth, 1, 1)

    # Pack BSJB at file offset 0x300
    bsjb = 0x300
    ver = b"v4.0.30319\x00\x00"
    struct.pack_into("<IHHII", pe, bsjb, 0x424A5342, 1, 1, 0, len(ver))
    pe[bsjb + 16 : bsjb + 16 + len(ver)] = ver
    fp = bsjb + 16 + len(ver)
    struct.pack_into("<HH", pe, fp, 0, 4)  # 4 streams
    hdr_cur = fp + 4
    streams = [(b"#~\x00\x00", bytes(tbl)), (b"#Strings\x00\x00\x00\x00", strings), (b"#US\x00", us_heap), (b"#Blob\x00\x00\x00", blob_heap)]
    data_cur = hdr_cur + sum(8 + len(nm) for nm, _ in streams)
    for nm, sbytes in streams:
        struct.pack_into("<II", pe, hdr_cur, data_cur - bsjb, len(sbytes))
        hdr_cur += 8
        pe[hdr_cur : hdr_cur + len(nm)] = nm
        hdr_cur += len(nm)
        pe[data_cur : data_cur + len(sbytes)] = sbytes
        data_cur += len(sbytes)

    res = decompile_dotnet_ecma335(bytes(pe), assembly_name="CoreAsm")
    assert res["status"] == "complete"
    assert "CipherBox.cs" in res["cs_files"]
    cs_src = res["cs_files"]["CipherBox.cs"]
    assert "public static int MixKeys(int p0, int p1)" in cs_src
    assert "((p0 + p1) ^ 5)" in cs_src


def test_v105_apk_full_axml_and_jni_elf_bridge(tmp_path: Path) -> None:
    # 1. Build real AXML StringPool + <manifest package="com.aether.sec"><uses-permission android:name="android.permission.INTERNET"/></manifest>
    strs = ["manifest", "package", "com.aether.sec", "uses-permission", "name", "android.permission.INTERNET"]
    sp_data = bytearray()
    offsets = []
    for s in strs:
        offsets.append(len(sp_data))
        enc = s.encode("utf-16-le")
        sp_data += struct.pack("<H", len(s)) + enc + b"\x00\x00"
    while len(sp_data) % 4:
        sp_data.append(0)
    sp_hdr_sz = 28
    str_start = sp_hdr_sz + len(offsets) * 4
    sp_chunk = struct.pack("<HHIIIIII", 0x0001, 28, str_start + len(sp_data), len(strs), 0, 0, str_start, 0)
    for o in offsets:
        sp_chunk += struct.pack("<I", o)
    sp_chunk += sp_data

    # START_ELEMENT <manifest package="com.aether.sec">
    e1_attr = struct.pack("<IIIHBBI", 0xFFFFFFFF, 1, 2, 0x0800, 0, 0x03, 2)
    e1 = struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36 + 20, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0x14, 20, 1, 0, 0, 0) + e1_attr
    e2_attr = struct.pack("<IIIHBBI", 0x00000000, 4, 5, 0x0800, 0, 0x03, 5)
    e2 = struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36 + 20, 2, 0xFFFFFFFF, 0xFFFFFFFF, 3, 0x14, 20, 1, 0, 0, 0) + e2_attr
    e2_end = struct.pack("<HHIIIII", 0x0103, 16, 24, 2, 0xFFFFFFFF, 0xFFFFFFFF, 3)
    e1_end = struct.pack("<HHIIIII", 0x0103, 16, 24, 3, 0xFFFFFFFF, 0xFFFFFFFF, 0)

    axml = struct.pack("<HHI", 0x0003, 8, 8 + len(sp_chunk) + len(e1) + len(e2) + len(e2_end) + len(e1_end)) + sp_chunk + e1 + e2 + e2_end + e1_end
    decoded_xml = decode_axml_binary(axml)
    assert '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.aether.sec">' in decoded_xml
    assert '<uses-permission android:name="android.permission.INTERNET">' in decoded_xml

    # 2. Build APK with ELF64 .so exporting Java_com_aether_sec_NativeVault_deriveKey
    elf = bytearray(0x400)
    elf[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    # Minimal ELF64 with .shstrtab (1), .strtab (2), .symtab (3)
    shstr = b"\x00.shstrtab\x00.strtab\x00.symtab\x00"
    strtab = b"\x00Java_com_aether_sec_NativeVault_deriveKey\x00"
    sym0 = b"\x00" * 24
    sym1 = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x1234, 16)
    symtab = sym0 + sym1
    elf[0x100 : 0x100 + len(shstr)] = shstr
    elf[0x140 : 0x140 + len(strtab)] = strtab
    elf[0x1C0 : 0x1C0 + len(symtab)] = symtab
    shoff = 0x240
    struct.pack_into("<HHIQQQIHHHHHH", elf, 16, 3, 0xB7, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 4, 1)
    # 4 section headers of 64 bytes each
    # Sec 0: SHT_NULL
    # Sec 1: .shstrtab (type 3)
    struct.pack_into("<IIQQQQIIQQ", elf, shoff + 64, 1, 3, 0, 0, 0x100, len(shstr), 0, 0, 1, 0)
    # Sec 2: .strtab (type 3)
    struct.pack_into("<IIQQQQIIQQ", elf, shoff + 128, 11, 3, 0, 0, 0x140, len(strtab), 0, 0, 1, 0)
    # Sec 3: .symtab (type 2, link=2, entsize=24)
    struct.pack_into("<IIQQQQIIQQ", elf, shoff + 192, 19, 2, 0, 0, 0x1C0, len(symtab), 2, 1, 8, 24)

    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", axml)
        zf.writestr("lib/arm64-v8a/libvault.so", bytes(elf))
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 104)

    res_apk = reconstruct_dex_apk_project(apk_path, tmp_path / "apk_proj")
    assert "jni_native_bridge_map.json" in res_apk["generated_files"]
    jmap = json.loads((tmp_path / "apk_proj" / "jni_native_bridge_map.json").read_text(encoding="utf-8"))
    assert jmap["jni_symbols"][0]["elf_symbol"] == "Java_com_aether_sec_NativeVault_deriveKey"
    assert jmap["jni_symbols"][0]["java_class"] == "com.aether.sec.NativeVault"


def test_v105_wasm_f64_and_call_indirect_live_dll(tmp_path: Path) -> None:
    # Build real .wasm with:
    #   func 0: add_mul(a, b) -> (a + b) * 3
    #   func 1: calc_f64() -> i32.trunc_f64_s(f64.add(12.5, 3.5)) = 16
    #   func 2: call_ind(slot, x, y) -> call_indirect(type0) = (x+y)*3
    t0 = b"\x60\x02\x7e\x7e\x01\x7e"  # (i64, i64) -> i64
    t1 = b"\x60\x00\x01\x7e"          # () -> i64
    t2 = b"\x60\x03\x7e\x7e\x7e\x01\x7e"  # (i64, i64, i64) -> i64
    sec_type = _wasm_sec(1, _uleb(3) + t0 + t1 + t2)
    sec_fn = _wasm_sec(3, _uleb(3) + b"\x00\x01\x02")
    sec_exp = _wasm_sec(7, _uleb(3) + b"\x06add_fn\x00\x00" + b"\x08calc_f64\x00\x01" + b"\x08call_ind\x00\x02")
    # Element section (id=9): 1 segment, table 0, i32.const 0 (0x41 0x00 0x0b), count 1, func 0
    sec_elem = _wasm_sec(9, _uleb(1) + _uleb(0) + b"\x41\x00\x0b" + _uleb(1) + _uleb(0))
    # Code bodies
    # f0: local.get 0, local.get 1, i64.add(0x7c), i64.const 3(0x42 0x03), i64.mul(0x7e), end(0x0b)
    b0 = b"\x00\x20\x00\x20\x01\x7c\x42\x03\x7e\x0b"
    # f1: f64.const 12.5, f64.const 3.5, f64.add(0xa0), i32.trunc_f64_s(0xaa), i64.extend_i32_s(0xac), end(0x0b)
    b1 = b"\x00\x44" + struct.pack("<d", 12.5) + b"\x44" + struct.pack("<d", 3.5) + b"\xa0\xaa\xac\x0b"
    # f2: local.get 1, local.get 2, local.get 0, call_indirect(0x11, type=0, tbl=0), end
    b2 = b"\x00\x20\x01\x20\x02\x20\x00\x11\x00\x00\x0b"
    sec_code = _wasm_sec(10, _uleb(3) + _uleb(len(b0)) + b0 + _uleb(len(b1)) + b1 + _uleb(len(b2)) + b2)

    wasm_p = tmp_path / "poly.wasm"
    wasm_p.write_bytes(b"\x00asm\x01\x00\x00\x00" + sec_type + sec_fn + sec_exp + sec_elem + sec_code)
    out_w = tmp_path / "wasm_out"
    w_res = reconstruct_wasm_project(wasm_p, out_w)
    assert w_res["functions_lifted"] == 3

    tc = _find_msvc_x64_toolchain()
    assert tc and tc[2]
    cl_exe, msvc_env = tc[2], tc[1]
    dll_p = tmp_path / "wasm_rec.dll"
    bld = subprocess.run(
        [cl_exe, "/nologo", "/O2", "/LD", str(out_w / "src" / "wasm_module.c"), f"/Fe:{dll_p}"],
        cwd=str(out_w),
        env=msvc_env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert bld.returncode == 0, bld.stdout + bld.stderr
    wdll = ctypes.CDLL(str(dll_p))
    wdll.calc_f64.restype = ctypes.c_int64
    wdll.call_ind.argtypes = [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64]
    wdll.call_ind.restype = ctypes.c_int64
    assert wdll.calc_f64() == 16
    assert wdll.call_ind(0, 4, 6) == 30


def test_v105_js_sourcemap_hermes_and_go_rust_types(tmp_path: Path) -> None:
    # 1. JS Inline SourceMap + Hermes HBC detection
    sm_obj = {"version": 3, "sources": ["src/auth.ts"], "sourcesContent": ["export const signToken = (x: number) => x ^ 0x55;\n"]}
    b64_sm = base64.b64encode(json.dumps(sm_obj).encode("utf-8")).decode("ascii")
    bundle_p = tmp_path / "app.bundle.js"
    bundle_p.write_text(f"export const a = 1;\n//# sourceMappingURL=data:application/json;base64,{b64_sm}\n", encoding="utf-8")
    js_out = tmp_path / "js_proj"
    j_res = reconstruct_js_bundle_project(bundle_p, js_out)
    assert "src/recovered_sources/auth.ts" in j_res["generated_files"]
    assert "signToken" in (js_out / "src" / "recovered_sources" / "auth.ts").read_text(encoding="utf-8")

    # Hermes .hbc
    hbc_p = tmp_path / "index.android.bundle"
    hbc_p.write_bytes(b"\xC6\x1F\xBC\x03\xC1\x03\x19\x1F" + struct.pack("<I", 96) + b"secretEndpointUrl\x00" + b"\x00" * 32)
    hbc_out = tmp_path / "hbc_proj"
    h_res = reconstruct_js_bundle_project(hbc_p, hbc_out)
    assert "src/hermes_strings.json" in h_res["generated_files"]

    # 2. Go itab/type & Rust trait vtable recovery
    go_blob = bytearray(512)
    # Minimal valid pclntab v1.20+ (0xFFFFFFF1) or simply inject a realistic Go pclntab from minimal Go layout + go.itab strings
    # Use a 1-entry Go 1.20 pclntab header:
    # magic=0xFFFFFFF1, pad=0,0, minLC=1, ptrSize=8
    struct.pack_into("<IHHHH", go_blob, 0, 0xFFFFFFF1, 0, 1 | (8 << 8), 0, 0)  # wait exact bytes 4..8: 0,0,1,8
    go_blob[0:8] = struct.pack("<IBBBB", 0xFFFFFFF1, 0, 0, 1, 8)
    # fields[0..7] (Q * 8) at off 8..72: nfunc=1, nfiles=0, textStart=0x1000, funcnameOff=80, cuOff=0, filetabOff=0, pctabOff=0, pclnOff=120
    struct.pack_into("<8Q", go_blob, 8, 1, 0, 0x1000, 80, 0, 0, 0, 120)
    go_blob[80:90] = b"main.main\x00"
    # functab at 120: entry=0, func_off=16 (relative to functab=120 -> record at 136), sentinel entry=16
    struct.pack_into("<III", go_blob, 120, 0, 16, 16)
    struct.pack_into("<Ii", go_blob, 136, 0, 0)
    go_blob += b"\x00go.itab.*main.FastHasher,main.Hasher\x00type:main.SessionConfig\x00"
    go_res = reconstruct_go_project(bytes(go_blob), tmp_path / "go_proj")
    assert "pkg/recovered_types/types.go" in go_res["generated_files"]

    rust_blob = b"rustc/1.78.0 (9b00956e5 2024-04-29)\x00_ZN42_$LT$VaultImpl$u20$as$u20$Encryptor$GT$4seal17h0123456789abcdefE\x00"
    rs_res = reconstruct_rust_project(rust_blob, tmp_path / "rust_proj")
    assert "src/traits_recovered.rs" in rs_res["generated_files"]
    assert "pub trait Encryptor" in (tmp_path / "rust_proj" / "src" / "traits_recovered.rs").read_text(encoding="utf-8")
