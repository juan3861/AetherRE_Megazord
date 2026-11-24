"""AetherRE Megazord v8.0 — Full Project Reconstructors for Managed, Bytecode, WASM & Web Ecosystems.

Converts passive forensic scanners into true compilable/runnable project generators:
  1. .NET / CLR (.dll/.exe with BSJB) -> .sln + .csproj + .cs via ilspycmd (+ dotnet build verification)
  2. Android APK / DEX / JAR -> AndroidManifest.xml (AXML decoded) + Java sources + build.gradle (+ javac verification)
  3. Python .pyc / .pyz / PyInstaller -> Python 3.x bytecode decompiler + pyproject.toml + requirements.txt
  4. WebAssembly .wasm -> Full Type/Import/Export/Code stack-machine lifter to C99 + WASI shim + CMakeLists.txt
  5. JS / Webpack Bundles -> Module unbundling + semantic TS/ESM reconstruction + package.json + tsconfig.json
"""

from __future__ import annotations

import dis
import hashlib
import io
import json
import marshal
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aether_re.dex_forensics import _read_uleb128, parse_dex_bytes
from aether_re.dotnet_forensics import analyze_dotnet_metadata
from aether_re.semantic_deobfuscator import deobfuscate_javascript_snippet
from aether_re.wasm_forensics import WASM_MAGIC, _read_wasm_string, analyze_wasm_bytes

SCHEMA = "re-megazord-managed-reconstructor.v1"


# ---------------------------------------------------------------------------
# 1. .NET / CLR Project Reconstructor (ilspycmd + BSJB fallback)
# ---------------------------------------------------------------------------

def reconstruct_dotnet_project(
    target_path: str | Path,
    output_dir: str | Path,
    *,
    build_verify: bool = True,
) -> Dict[str, Any]:
    """Reconstructs a compilable C# .csproj/.cs project from a .NET assembly."""
    t_path = Path(target_path).resolve()
    out_root = Path(output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    raw = t_path.read_bytes()
    meta = analyze_dotnet_metadata(raw)
    if not meta.get("is_dotnet"):
        return {"schema": SCHEMA, "status": "not_dotnet", "generated_files": []}

    ilspy_bin = shutil.which("ilspycmd")
    if ilspy_bin is None:
        cand = Path.home() / ".dotnet" / "tools" / "ilspycmd.exe"
        if cand.is_file():
            ilspy_bin = str(cand)

    generated: List[str] = []
    used_ilspy = False
    decompile_err: Optional[str] = None
    if ilspy_bin:
        try:
            proc = subprocess.run(
                [ilspy_bin, "-p", "-o", str(out_root), str(t_path)],
                capture_output=True,
                text=True,
                timeout=90,
            )
            cs_files = [
                p.relative_to(out_root).as_posix()
                for p in sorted(out_root.rglob("*"))
                if p.is_file() and p.suffix.lower() in (".cs", ".csproj", ".sln", ".resx", ".json")
            ]
            if proc.returncode == 0 and any(f.endswith(".cs") for f in cs_files):
                used_ilspy = True
                generated = cs_files
            else:
                decompile_err = (proc.stderr or proc.stdout or f"rc={proc.returncode}")[:400]
        except Exception as exc:
            decompile_err = str(exc)[:400]

    if not used_ilspy:
        # Pure-Python BSJB metadata C# skeleton fallback
        asm_name = re.sub(r"[^A-Za-z0-9_]", "_", t_path.stem) or "ReconstructedAsm"
        csproj = "\n".join([
            '<Project Sdk="Microsoft.NET.Sdk">',
            "  <PropertyGroup>",
            "    <OutputType>Library</OutputType>",
            "    <TargetFramework>net8.0</TargetFramework>",
            f"    <AssemblyName>{asm_name}</AssemblyName>",
            "  </PropertyGroup>",
            "</Project>",
            "",
        ])
        (out_root / f"{asm_name}.csproj").write_text(csproj, encoding="utf-8")
        str_comments = "\n".join(f"// #US: {u!r}" for u in (meta.get("user_strings") or [])[:40])
        cs_src = "\n".join([
            f"// Fallback BSJB Metadata Reconstruction ({meta.get('runtime_version')})",
            str_comments,
            f"namespace {asm_name};",
            "public static class RecoveredEntry {",
            "    public static int Run() => 0;",
            "}",
            "",
        ])
        (out_root / "RecoveredEntry.cs").write_text(cs_src, encoding="utf-8")
        generated = [f"{asm_name}.csproj", "RecoveredEntry.cs"]

    dotnet_build_passed: Optional[bool] = None
    dotnet_build_log = ""
    dotnet_bin = shutil.which("dotnet")
    csproj_files = sorted(out_root.glob("*.csproj"))
    if build_verify and dotnet_bin and csproj_files:
        try:
            b_proc = subprocess.run(
                [dotnet_bin, "build", str(csproj_files[0]), "--nologo", "-c", "Release"],
                capture_output=True,
                text=True,
                timeout=90,
            )
            dotnet_build_passed = (b_proc.returncode == 0)
            dotnet_build_log = (b_proc.stdout + "\n" + b_proc.stderr).strip()[:600]
        except Exception as exc:
            dotnet_build_passed = False
            dotnet_build_log = str(exc)[:400]

    return {
        "schema": SCHEMA,
        "status": "complete",
        "project_kind": "dotnet_csharp",
        "used_ilspycmd": used_ilspy,
        "runtime_version": meta.get("runtime_version"),
        "generated_files": generated,
        "dotnet_build_passed": dotnet_build_passed,
        "dotnet_build_log": dotnet_build_log,
        "decompile_error": decompile_err,
    }


# ---------------------------------------------------------------------------
# 2. Android APK / DEX / JAR Reconstructor (AXML + Dalvik-to-Java)
# ---------------------------------------------------------------------------

def decode_axml_binary(axml_bytes: bytes) -> str:
    """Minimal pure-Python decoder extracting strings/elements from Android Binary XML (AXML)."""
    if len(axml_bytes) < 16 or struct.unpack_from("<H", axml_bytes, 0)[0] != 0x0003:
        return axml_bytes.decode("utf-8", errors="replace") if axml_bytes.lstrip().startswith(b"<") else ""
    # Parse StringPool chunk right after ResXMLTree_header (8 bytes)
    strings: List[str] = []
    if len(axml_bytes) >= 36 and struct.unpack_from("<H", axml_bytes, 8)[0] == 0x0001:
        sp_size = struct.unpack_from("<I", axml_bytes, 12)[0]
        scount = struct.unpack_from("<I", axml_bytes, 16)[0]
        flags = struct.unpack_from("<I", axml_bytes, 24)[0]
        str_start = 8 + struct.unpack_from("<I", axml_bytes, 28)[0]
        is_utf8 = bool(flags & (1 << 8))
        offsets_base = 36
        for i in range(min(scount, 4096)):
            if offsets_base + (i + 1) * 4 > len(axml_bytes):
                break
            off = str_start + struct.unpack_from("<I", axml_bytes, offsets_base + i * 4)[0]
            if off >= len(axml_bytes):
                strings.append("")
                continue
            if is_utf8:
                _u16l = axml_bytes[off]
                p = off + (2 if (_u16l & 0x80) else 1)
                blen = axml_bytes[p] if p < len(axml_bytes) else 0
                p += (2 if (blen & 0x80) else 1)
                strings.append(axml_bytes[p : p + blen].split(b"\x00", 1)[0].decode("utf-8", errors="replace"))
            else:
                if off + 2 <= len(axml_bytes):
                    clen = struct.unpack_from("<H", axml_bytes, off)[0]
                    raw_u16 = axml_bytes[off + 2 : off + 2 + clen * 2]
                    strings.append(raw_u16.decode("utf-16-le", errors="replace"))
        pos = 8 + sp_size
    else:
        pos = len(axml_bytes)

    pkg_guess = next((s for s in strings if "." in s and "android" not in s.lower() and " " not in s and len(s) > 3), "com.reconstructed.app")
    attrs_notes = "\n".join(f"<!-- AXML token: {s} -->" for s in strings[:40] if s and len(s) < 120)
    return "\n".join([
        '<?xml version="1.0" encoding="utf-8"?>',
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg_guess}">',
        attrs_notes,
        '    <application android:label="@string/app_name" />',
        "</manifest>",
        "",
    ])


def _disasm_dalvik_code_item(dex: bytes, code_off: int, strings: List[str], methods: List[str]) -> List[str]:
    """Lifts basic Dalvik bytecode registers (const/4, add-int, sub-int, mul-int, return) to Java lines."""
    if code_off <= 0 or code_off + 16 > len(dex):
        return ["        return 0;"]
    regs_sz, ins_sz, _outs, _tries, _dbg, insns_size = struct.unpack_from("<HHHHII", dex, code_off)
    insns_base = code_off + 16
    if insns_base + insns_size * 2 > len(dex):
        return ["        return 0;"]
    u16 = [struct.unpack_from("<H", dex, insns_base + i * 2)[0] for i in range(insns_size)]
    decls = ", ".join(f"v{i} = 0" for i in range(max(1, min(regs_sz, 16))))
    jlines: List[str] = [f"        int {decls};"]
    param_base = max(0, regs_sz - ins_sz)
    for pi in range(min(ins_sz, 2)):
        pname = "a" if pi == 0 else "b"
        if param_base + pi < 16:
            jlines.append(f"        v{param_base + pi} = {pname};")
    ip = 0
    while ip < len(u16):
        w0 = u16[ip]
        op = w0 & 0xFF
        if op == 0x00:  # nop
            ip += 1
        elif op == 0x0E:  # return-void
            jlines.append("        return;")
            ip += 1
        elif op == 0x0F:  # return vAA
            vA = (w0 >> 8) & 0xFF
            jlines.append(f"        return v{vA};")
            ip += 1
        elif op == 0x12:  # const/4 vA, #+B
            vA = (w0 >> 8) & 0xF
            imm = (w0 >> 12) & 0xF
            if imm >= 8:
                imm -= 16
            jlines.append(f"        v{vA} = {imm};")
            ip += 1
        elif op == 0x13 and ip + 1 < len(u16):  # const/16 vAA, #+BBBB
            vA = (w0 >> 8) & 0xFF
            imm = struct.unpack("<h", struct.pack("<H", u16[ip + 1]))[0]
            jlines.append(f"        v{vA} = {imm};")
            ip += 2
        elif op in (0xD8, 0xD9, 0xDA, 0xDD, 0xDE, 0xDF) and ip + 1 < len(u16):  # /lit8
            vA = (w0 >> 8) & 0xFF
            vB = u16[ip + 1] & 0xFF
            imm = struct.unpack("<b", bytes([(u16[ip + 1] >> 8) & 0xFF]))[0]
            cop = {0xD8: "+", 0xD9: "-", 0xDA: "*", 0xDD: "&", 0xDE: "|", 0xDF: "^"}[op]
            jlines.append(f"        v{vA} = v{vB} {cop} ({imm});")
            ip += 2
        elif op in (0x90, 0x91, 0x92, 0x95, 0x96, 0x97) and ip + 1 < len(u16):
            # 23x: op vAA, vBB, vCC
            vA = (w0 >> 8) & 0xFF
            vB = u16[ip + 1] & 0xFF
            vC = (u16[ip + 1] >> 8) & 0xFF
            cop = {0x90: "+", 0x91: "-", 0x92: "*", 0x95: "&", 0x96: "|", 0x97: "^"}[op]
            jlines.append(f"        v{vA} = v{vB} {cop} v{vC};")
            ip += 2
        elif op in (0xB0, 0xB1, 0xB2, 0xB5, 0xB6, 0xB7):  # /2addr
            vA = (w0 >> 8) & 0xF
            vB = (w0 >> 12) & 0xF
            cop = {0xB0: "+", 0xB1: "-", 0xB2: "*", 0xB5: "&", 0xB6: "|", 0xB7: "^"}[op]
            jlines.append(f"        v{vA} = v{vA} {cop} v{vB};")
            ip += 1
        elif op in (0xD0, 0xD1, 0xD2) and ip + 1 < len(u16):  # /lit16
            vA = (w0 >> 8) & 0xF
            vB = (w0 >> 12) & 0xF
            imm = struct.unpack("<h", struct.pack("<H", u16[ip + 1]))[0]
            cop = {0xD0: "+", 0xD1: "-", 0xD2: "*"}[op]
            jlines.append(f"        v{vA} = v{vB} {cop} ({imm});")
            ip += 2
        else:
            ip += 1
    if not any(l.strip().startswith("return") for l in jlines):
        jlines.append("        return 0;")
    return jlines


def _decode_dex_classes_to_java(dex: bytes) -> Dict[str, str]:
    """Parses DEX class_defs -> encoded_method -> Java source files."""
    if len(dex) < 0x70 or not dex.startswith(b"dex\n"):
        return {}
    rep = parse_dex_bytes(dex)
    # Walk strings/types directly for class_defs lookup
    str_cnt, str_off, typ_cnt, typ_off = struct.unpack_from("<IIII", dex, 0x38)
    mth_cnt, mth_off, cls_cnt, cls_off = struct.unpack_from("<IIII", dex, 0x58)

    strings: List[str] = []
    for i in range(min(str_cnt, 50_000)):
        so = struct.unpack_from("<I", dex, str_off + i * 4)[0]
        _, p = _read_uleb128(dex, so)
        end = dex.find(b"\x00", p, min(len(dex), p + 512))
        strings.append(dex[p:end].decode("utf-8", errors="replace") if end != -1 else "")
    types = [strings[struct.unpack_from("<I", dex, typ_off + i * 4)[0]] if struct.unpack_from("<I", dex, typ_off + i * 4)[0] < len(strings) else "" for i in range(min(typ_cnt, 50_000))]
    methods_lbl: List[str] = []
    for i in range(min(mth_cnt, 50_000)):
        _c, _p, name_idx = struct.unpack_from("<HHI", dex, mth_off + i * 8)
        methods_lbl.append(strings[name_idx] if name_idx < len(strings) else f"m_{i}")

    java_files: Dict[str, str] = {}
    for ci in range(min(cls_cnt, 500)):
        c_idx, acc_flags, _sup, _ifaces, _src_idx, _ann, class_data_off, _st = struct.unpack_from("<IIIIIIII", dex, cls_off + ci * 32)
        desc = types[c_idx] if c_idx < len(types) else f"LClass_{ci};"
        fqcn = desc.lstrip("L").rstrip(";").replace("/", ".")
        if not fqcn or "$" in fqcn:
            continue
        pkg, _, cls_name = fqcn.rpartition(".")
        cls_name = re.sub(r"[^A-Za-z0-9_]", "_", cls_name) or f"Class_{ci}"
        rel_java = (pkg.replace(".", "/") + "/" if pkg else "") + f"{cls_name}.java"
        lines = []
        if pkg:
            lines.append(f"package {pkg};")
            lines.append("")
        lines.append(f"public class {cls_name} {{")

        if class_data_off and class_data_off < len(dex):
            pos = class_data_off
            sf_sz, pos = _read_uleb128(dex, pos)
            if_sz, pos = _read_uleb128(dex, pos)
            dm_sz, pos = _read_uleb128(dex, pos)
            vm_sz, pos = _read_uleb128(dex, pos)
            for _ in range(sf_sz + if_sz):
                _, pos = _read_uleb128(dex, pos)
                _, pos = _read_uleb128(dex, pos)
            m_idx = 0
            for grp_idx, cnt in enumerate((dm_sz, vm_sz)):
                if grp_idx == 1:
                    m_idx = 0
                for _ in range(cnt):
                    delta, pos = _read_uleb128(dex, pos)
                    _m_flags, pos = _read_uleb128(dex, pos)
                    code_off, pos = _read_uleb128(dex, pos)
                    m_idx += delta
                    m_name = methods_lbl[m_idx] if m_idx < len(methods_lbl) else f"method_{m_idx}"
                    if m_name in ("<init>", "<clinit>"):
                        continue
                    safe_m = re.sub(r"[^A-Za-z0-9_]", "_", m_name)
                    body_lines = _disasm_dalvik_code_item(dex, code_off, strings, methods_lbl) if code_off else ["        return 0;"]
                    ret_ty = "void" if any(l.strip() == "return;" for l in body_lines) else "int"
                    lines.append(f"    public static {ret_ty} {safe_m}(int a, int b) {{")
                    lines.extend(body_lines)
                    lines.append("    }")
                    lines.append("")
        lines.append("}")
        java_files[rel_java] = "\n".join(lines) + "\n"
    return java_files


def _decode_jvm_class_to_java(cls: bytes) -> Optional[Tuple[str, str]]:
    """Minimal pure-Python JVM .class (0xCAFEBABE) constant-pool & Code bytecode lifter -> .java."""
    if len(cls) < 16 or not cls.startswith(b"\xca\xfe\xba\xbe"):
        return None
    cp_count = struct.unpack_from(">H", cls, 8)[0]
    pos = 10
    cp: Dict[int, Any] = {}
    i = 1
    while i < cp_count and pos < len(cls):
        tag = cls[pos]
        pos += 1
        if tag == 1:  # Utf8
            ln = struct.unpack_from(">H", cls, pos)[0]
            pos += 2
            cp[i] = ("utf8", cls[pos : pos + ln].decode("utf-8", errors="replace"))
            pos += ln
        elif tag in (3, 4):
            cp[i] = ("num", struct.unpack_from(">i" if tag == 3 else ">f", cls, pos)[0])
            pos += 4
        elif tag in (5, 6):
            cp[i] = ("num64", struct.unpack_from(">q" if tag == 5 else ">d", cls, pos)[0])
            pos += 8
            i += 1
        elif tag in (7, 8, 16, 19, 20):
            cp[i] = ("ref", tag, struct.unpack_from(">H", cls, pos)[0])
            pos += 2
        elif tag in (9, 10, 11, 12, 17, 18):
            cp[i] = ("pair", tag, struct.unpack_from(">HH", cls, pos))
            pos += 4
        elif tag == 15:
            pos += 3
        else:
            return None
        i += 1

    def _utf8(idx: int) -> str:
        item = cp.get(idx)
        return item[1] if item and item[0] == "utf8" else ""

    def _cls_name(idx: int) -> str:
        item = cp.get(idx)
        if item and item[0] == "ref":
            return _utf8(item[2])
        return "RecoveredClass"

    def _methodref_info(idx: int) -> Tuple[str, str, str]:
        item = cp.get(idx)
        if item and item[0] == "pair":
            cls_idx, nat_idx = item[2]
            c_nm = _cls_name(cls_idx)
            nat = cp.get(nat_idx)
            if nat and nat[0] == "pair":
                n_idx, d_idx = nat[2]
                return c_nm, _utf8(n_idx), _utf8(d_idx)
        return "", f"method_{idx}", "()I"

    def _fieldref_info(idx: int) -> Tuple[str, str, str]:
        return _methodref_info(idx)

    def _jvm_type_from_desc(d: str) -> str:
        if d == "J":
            return "long"
        if d in ("I", "Z", "B", "C", "S"):
            return "int"
        if d == "Ljava/lang/String;":
            return "String"
        return "Object"

    def _parse_jvm_params(desc: str, *, is_static: bool = True) -> Tuple[List[Tuple[str, int]], str]:
        inner = desc[desc.find("(") + 1 : desc.find(")")] if "(" in desc and ")" in desc else ""
        ret_raw = desc[desc.find(")") + 1 :] if ")" in desc else "I"
        ptypes: List[Tuple[str, int]] = []
        slot = 0 if is_static else 1
        pi = 0
        while pi < len(inner):
            ch = inner[pi]
            if ch in ("I", "Z", "B", "C", "S"):
                ptypes.append(("int", slot))
                slot += 1
                pi += 1
            elif ch == "J":
                ptypes.append(("long", slot))
                slot += 2
                pi += 1
            elif ch == "L":
                end_l = inner.find(";", pi)
                pi = (end_l + 1) if end_l != -1 else len(inner)
                ptypes.append(("Object", slot))
                slot += 1
            elif ch == "[":
                pi += 1
                if pi < len(inner) and inner[pi] == "L":
                    end_l = inner.find(";", pi)
                    pi = (end_l + 1) if end_l != -1 else len(inner)
                elif pi < len(inner):
                    pi += 1
                ptypes.append(("Object", slot))
                slot += 1
            else:
                pi += 1
        ret_t = "void" if ret_raw == "V" else ("long" if ret_raw == "J" else "int")
        return ptypes, ret_t

    if pos + 6 > len(cls):
        return None
    _acc, this_cls_idx, _super_idx = struct.unpack_from(">HHH", cls, pos)
    pos += 6
    if_cnt = struct.unpack_from(">H", cls, pos)[0]
    pos += 2 + if_cnt * 2
    fld_cnt = struct.unpack_from(">H", cls, pos)[0]
    pos += 2
    parsed_fields: List[Tuple[int, str, str]] = []
    for _ in range(fld_cnt):
        if pos + 8 > len(cls):
            break
        f_acc, f_name_idx, f_desc_idx, ac_cnt = struct.unpack_from(">HHHH", cls, pos)
        pos += 8
        parsed_fields.append((f_acc, _utf8(f_name_idx), _utf8(f_desc_idx)))
        for _ in range(ac_cnt):
            alen = struct.unpack_from(">I", cls, pos + 2)[0]
            pos += 6 + alen

    if pos + 2 > len(cls):
        return None
    mth_cnt = struct.unpack_from(">H", cls, pos)[0]
    pos += 2

    this_cls_raw = _cls_name(this_cls_idx)
    fqcn_raw = this_cls_raw.replace("/", ".")
    pkg, _, cls_simple = fqcn_raw.rpartition(".")
    cls_simple = re.sub(r"[^A-Za-z0-9_]", "_", cls_simple) or "RecoveredClass"
    rel_java = (pkg.replace(".", "/") + "/" if pkg else "") + f"{cls_simple}.java"

    lines: List[str] = []
    if pkg:
        lines.extend([f"package {pkg};", ""])
    lines.append(f"public class {cls_simple} {{")
    for f_acc, f_name, f_desc in parsed_fields:
        if (f_acc & 0x1000) or not f_name:  # skip synthetic
            continue
        f_ty = _jvm_type_from_desc(f_desc)
        if f_ty == "Object":
            continue
        stat_kw = "static " if (f_acc & 0x0008) else ""
        safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", f_name)
        init_f = " = 0L" if (stat_kw and f_ty == "long") else (" = 0" if (stat_kw and f_ty == "int") else "")
        lines.append(f"    public {stat_kw}{f_ty} {safe_fn}{init_f};")
    if parsed_fields:
        lines.append("")

    _JVM_BR_OPS = {
        0x99: ("zero", "=="), 0x9A: ("zero", "!="), 0x9B: ("zero", "<"),
        0x9C: ("zero", ">="), 0x9D: ("zero", ">"), 0x9E: ("zero", "<="),
        0x9F: ("icmp", "=="), 0xA0: ("icmp", "!="), 0xA1: ("icmp", "<"),
        0xA2: ("icmp", ">="), 0xA3: ("icmp", ">"), 0xA4: ("icmp", "<="),
        0xA7: ("goto", ""),
    }

    def _decode_jvm_insns(bc: bytes) -> Tuple[List[Tuple[int, int, int, int]], Set[int], bool]:
        insns: List[Tuple[int, int, int, int]] = []
        targets: Set[int] = set()
        has_cf = False
        p = 0
        while p < len(bc):
            pc = p
            op = bc[p]
            p += 1
            arg = 0
            if op in (0x10, 0x12, 0x15, 0x16, 0x19, 0x36, 0x37, 0x3A):  # u1/s1
                if p < len(bc):
                    arg = struct.unpack("<b", bytes([bc[p]]))[0] if op == 0x10 else bc[p]
                    p += 1
                if op in (0x36, 0x37, 0x3A):
                    has_cf = True
            elif op in (0x11, 0x13, 0x14, 0xB8):  # u2/s2
                if p + 1 < len(bc):
                    arg = struct.unpack_from(">h" if op == 0x11 else ">H", bc, p)[0]
                    p += 2
            elif op == 0x84:  # iinc idx const
                if p + 1 < len(bc):
                    idx_i = bc[p]
                    c_i = struct.unpack("<b", bytes([bc[p + 1]]))[0]
                    arg = (idx_i << 16) | (c_i & 0xFFFF)
                    p += 2
                    has_cf = True
            elif op in _JVM_BR_OPS:
                if p + 1 < len(bc):
                    off_b = struct.unpack_from(">h", bc, p)[0]
                    arg = pc + off_b
                    targets.add(arg)
                    has_cf = True
                    p += 2
            elif op in (0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x4B, 0x4C, 0x4D, 0x4E):
                has_cf = True
            elif op in (0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB9, 0xBB):  # 2-byte CP ref
                if p + 1 < len(bc):
                    arg = struct.unpack_from(">H", bc, p)[0]
                    p += 2
                    if op in (0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xBB):
                        has_cf = True
            insns.append((pc, op, arg, p))
        return insns, targets, has_cf

    def _lift_jvm_code(bc: bytes, ptypes: List[Tuple[str, int]], max_locals: int, ret_t: str, *, is_static: bool = True) -> List[str]:
        insns, targets, has_cf = _decode_jvm_insns(bc)
        if not insns:
            return ["        return;" if ret_t == "void" else "        return 0;"]

        # Fast-path linear expression lifter for pure static branchless methods
        if is_static and not has_cf and all(op not in (0xB8, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7) for _, op, _, _ in insns):
            st: List[str] = []
            out_j: List[str] = []
            for _pc, op, arg, _np in insns:
                if 0x1A <= op <= 0x1D:
                    st.append(f"p{op - 0x1A}")
                elif op == 0x15:
                    st.append(f"p{arg}")
                elif 0x02 <= op <= 0x08:
                    st.append(str(op - 3))
                elif op in (0x10, 0x11):
                    st.append(str(arg))
                elif op in (0x60, 0x64, 0x68, 0x6C, 0x70, 0x7E, 0x80, 0x82) and len(st) >= 2:
                    b_e, a_e = st.pop(), st.pop()
                    mop = {0x60: "+", 0x64: "-", 0x68: "*", 0x6C: "/", 0x70: "%", 0x7E: "&", 0x80: "|", 0x82: "^"}[op]
                    st.append(f"({a_e} {mop} {b_e})")
                elif op == 0xAC:
                    out_j.append(f"        return {st.pop() if st else '0'};")
                elif op == 0xB1:
                    out_j.append("        return;")
            if out_j:
                return out_j

        # Structured CFG state machine supporting OOP `this`, fields, locals, branches, and calls
        slot_types: Dict[int, str] = {slot: ty for ty, slot in ptypes}
        slot_inits: Dict[int, str] = {slot: f"p{idx}" for idx, (_ty, slot) in enumerate(ptypes)}
        total_slots = max(max_locals, max(slot_types.keys(), default=0) + 1, 2)
        out: List[str] = []
        for s_idx in range(total_slots):
            ty = slot_types.get(s_idx, "int")
            init_v = slot_inits.get(s_idx, "0")
            if ty == "Object" or (not is_static and s_idx == 0):
                continue
            out.append(f"        long l{s_idx} = (long)({init_v});")
        out.append(f"        Object[] _ol = new Object[{max(total_slots, 4)}];")
        if not is_static:
            out.append("        _ol[0] = this;")
        for idx_p, (ty, slot) in enumerate(ptypes):
            if ty == "Object":
                out.append(f"        _ol[{slot}] = p{idx_p};")
        out.extend([
            "        long[] _st = new long[64];",
            "        Object[] _ost = new Object[64];",
            "        int _sp = 0;",
            "        int _pc = 0;",
            "        while (true) {",
            "            switch (_pc) {",
        ])

        for idx_i, (pc, op, arg, _np) in enumerate(insns):
            if idx_i == 0 or pc in targets:
                out.append(f"            case {pc}:")
            if op == 0x00:
                pass
            elif 0x02 <= op <= 0x08:  # iconst_m1..5
                out.append(f"                _st[_sp++] = {op - 3}L;")
            elif op in (0x09, 0x0A):  # lconst_0..1
                out.append(f"                _st[_sp++] = {op - 9}L;")
            elif op in (0x10, 0x11):  # bipush/sipush
                out.append(f"                _st[_sp++] = {arg}L;")
            elif op in (0x12, 0x13, 0x14):  # ldc/ldc_w/ldc2_w
                cp_ent = cp.get(arg)
                if cp_ent and cp_ent[0] in ("num", "num64") and isinstance(cp_ent[1], int):
                    out.append(f"                _st[_sp++] = {cp_ent[1]}L;")
                else:
                    out.append("                _st[_sp++] = 0L;")
            elif 0x1A <= op <= 0x1D:  # iload_0..3
                out.append(f"                _st[_sp++] = (int)l{op - 0x1A};")
            elif 0x1E <= op <= 0x21:  # lload_0..3
                out.append(f"                _st[_sp++] = l{op - 0x1E};")
            elif 0x2A <= op <= 0x2D:  # aload_0..3
                out.append(f"                _ost[_sp] = _ol[{op - 0x2A}]; _st[_sp++] = 0L;")
            elif op == 0x15:  # iload
                out.append(f"                _st[_sp++] = (int)l{arg};")
            elif op == 0x16:  # lload
                out.append(f"                _st[_sp++] = l{arg};")
            elif op == 0x19:  # aload
                out.append(f"                _ost[_sp] = _ol[{arg}]; _st[_sp++] = 0L;")
            elif 0x3B <= op <= 0x3E:  # istore_0..3
                out.append(f"                l{op - 0x3B} = (int)_st[--_sp];")
            elif 0x3F <= op <= 0x42:  # lstore_0..3
                out.append(f"                l{op - 0x3F} = _st[--_sp];")
            elif 0x4B <= op <= 0x4E:  # astore_0..3
                out.append(f"                _ol[{op - 0x4B}] = _ost[--_sp];")
            elif op == 0x36:  # istore
                out.append(f"                l{arg} = (int)_st[--_sp];")
            elif op == 0x37:  # lstore
                out.append(f"                l{arg} = _st[--_sp];")
            elif op == 0x3A:  # astore
                out.append(f"                _ol[{arg}] = _ost[--_sp];")
            elif op == 0x84:  # iinc
                i_slot = (arg >> 16) & 0xFF
                i_const = struct.unpack("<h", struct.pack("<H", arg & 0xFFFF))[0]
                out.append(f"                l{i_slot} = (int)((int)l{i_slot} + ({i_const}));")
            elif op == 0x57:  # pop
                out.append("                _sp--;")
            elif op == 0x59:  # dup
                out.append("                _st[_sp] = _st[_sp - 1]; _ost[_sp] = _ost[_sp - 1]; _sp++;")
            elif op == 0x74:  # ineg
                out.append("                _st[_sp - 1] = (int)(-(int)_st[_sp - 1]);")
            elif op == 0x75:  # lneg
                out.append("                _st[_sp - 1] = -_st[_sp - 1];")
            elif op == 0x85:  # i2l
                out.append("                _st[_sp - 1] = (long)(int)_st[_sp - 1];")
            elif op == 0x88:  # l2i
                out.append("                _st[_sp - 1] = (long)(int)_st[_sp - 1];")
            elif op in (0x60, 0x64, 0x68, 0x6C, 0x70, 0x78, 0x7A, 0x7C, 0x7E, 0x80, 0x82):
                iop = {
                    0x60: "+", 0x64: "-", 0x68: "*", 0x6C: "/", 0x70: "%",
                    0x78: "<<", 0x7A: ">>", 0x7C: ">>>", 0x7E: "&", 0x80: "|", 0x82: "^",
                }[op]
                out.append(
                    f"                {{ int _b = (int)_st[--_sp]; int _a = (int)_st[--_sp]; _st[_sp++] = (int)(_a {iop} _b); }}"
                )
            elif op in (0x61, 0x65, 0x69, 0x6D, 0x71):  # ladd/lsub/lmul/ldiv/lrem
                lop = {0x61: "+", 0x65: "-", 0x69: "*", 0x6D: "/", 0x71: "%"}[op]
                out.append(
                    f"                {{ long _b = _st[--_sp]; long _a = _st[--_sp]; _st[_sp++] = (_a {lop} _b); }}"
                )
            elif op == 0x94:  # lcmp
                out.append("                { long _b = _st[--_sp]; long _a = _st[--_sp]; _st[_sp++] = Long.compare(_a, _b); }")
            elif op in _JVM_BR_OPS:
                kind_b, cmp_b = _JVM_BR_OPS[op]
                if kind_b == "goto":
                    out.append(f"                {{ _pc = {arg}; continue; }}")
                elif kind_b == "zero":
                    out.append(f"                {{ int _a = (int)_st[--_sp]; if (_a {cmp_b} 0) {{ _pc = {arg}; continue; }} }}")
                else:
                    out.append(f"                {{ int _b = (int)_st[--_sp]; int _a = (int)_st[--_sp]; if (_a {cmp_b} _b) {{ _pc = {arg}; continue; }} }}")
            elif op == 0xB2:  # getstatic
                f_cls, f_nm, f_desc = _fieldref_info(arg)
                safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", f_nm)
                if f_cls == this_cls_raw and _jvm_type_from_desc(f_desc) in ("int", "long"):
                    out.append(f"                _st[_sp++] = {cls_simple}.{safe_fn};")
                else:
                    out.append("                _st[_sp++] = 0L;")
            elif op == 0xB3:  # putstatic
                f_cls, f_nm, f_desc = _fieldref_info(arg)
                safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", f_nm)
                fty = _jvm_type_from_desc(f_desc)
                if f_cls == this_cls_raw and fty in ("int", "long"):
                    out.append(f"                {cls_simple}.{safe_fn} = ({fty})_st[--_sp];")
                else:
                    out.append("                _sp--;")
            elif op == 0xB4:  # getfield
                f_cls, f_nm, f_desc = _fieldref_info(arg)
                safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", f_nm)
                if f_cls == this_cls_raw and _jvm_type_from_desc(f_desc) in ("int", "long"):
                    out.append(f"                _st[_sp - 1] = (({cls_simple})_ost[_sp - 1]).{safe_fn};")
                else:
                    out.append("                _st[_sp - 1] = 0L;")
            elif op == 0xB5:  # putfield
                f_cls, f_nm, f_desc = _fieldref_info(arg)
                safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", f_nm)
                fty = _jvm_type_from_desc(f_desc)
                if f_cls == this_cls_raw and fty in ("int", "long"):
                    out.append(
                        f"                {{ {fty} _fv = ({fty})_st[--_sp]; (({cls_simple})_ost[--_sp]).{safe_fn} = _fv; }}"
                    )
                else:
                    out.append("                _sp = Math.max(0, _sp - 2);")
            elif op in (0xB6, 0xB7, 0xB8):  # invokevirtual / invokespecial / invokestatic
                c_cls, c_m, c_desc = _methodref_info(arg)
                c_is_stat = (op == 0xB8)
                c_ptypes, c_ret = _parse_jvm_params(c_desc, is_static=c_is_stat)
                safe_cm = re.sub(r"[^A-Za-z0-9_]", "_", c_m)
                n_cargs = len(c_ptypes)
                if op == 0xB7 and c_m == "<init>":
                    if n_cargs > 0:
                        out.append(f"                _sp = Math.max(0, _sp - {n_cargs});")
                    out.append("                _sp = Math.max(0, _sp - 1);")
                elif c_cls == this_cls_raw or c_cls == "java/lang/Math":
                    out.append("                {")
                    arg_vars = []
                    for ai in range(n_cargs - 1, -1, -1):
                        aty, _ = c_ptypes[ai]
                        cast_t = "long" if aty == "long" else "int"
                        out.append(f"                    {cast_t} _ca{ai} = ({cast_t})_st[--_sp];")
                        arg_vars.insert(0, f"_ca{ai}")
                    if c_is_stat:
                        prefix = "Math." if c_cls == "java/lang/Math" else ""
                        call_expr = f"{prefix}{safe_cm}({', '.join(arg_vars)})"
                    else:
                        out.append(f"                    {cls_simple} _recv = ({cls_simple})_ost[--_sp];")
                        call_expr = f"_recv.{safe_cm}({', '.join(arg_vars)})"
                    if c_ret == "void":
                        out.append(f"                    {call_expr};")
                    else:
                        out.append(f"                    _st[_sp++] = {call_expr};")
                    out.append("                }")
                else:
                    pop_n = n_cargs + (0 if c_is_stat else 1)
                    if pop_n > 0:
                        out.append(f"                _sp = Math.max(0, _sp - {pop_n});")
                    if c_ret != "void":
                        out.append("                _st[_sp++] = 0L;")
            elif op == 0xBB:  # new
                out.append("                _ost[_sp] = null; _st[_sp++] = 0L;")
            elif op == 0xAC:  # ireturn
                out.append("                return (int)_st[--_sp];")
            elif op == 0xAD:  # lreturn
                out.append("                return _st[--_sp];")
            elif op == 0xB1:  # return
                out.append("                return;")

        fallback_ret = "return;" if ret_t == "void" else ("return 0L;" if ret_t == "long" else "return 0;")
        out.extend([
            f"            default: {fallback_ret}",
            "            }",
            "        }",
        ])
        return out

    for _ in range(mth_cnt):
        if pos + 8 > len(cls):
            break
        m_acc, m_name_idx, m_desc_idx, m_attr_cnt = struct.unpack_from(">HHHH", cls, pos)
        pos += 8
        m_name = _utf8(m_name_idx)
        m_desc = _utf8(m_desc_idx)
        code_bc = b""
        max_locals = 16
        for _ in range(m_attr_cnt):
            aname_idx, alen = struct.unpack_from(">HI", cls, pos)
            pos += 6
            if _utf8(aname_idx) == "Code" and alen >= 8:
                max_locals = max(1, struct.unpack_from(">H", cls, pos + 2)[0])
                code_len = struct.unpack_from(">I", cls, pos + 4)[0]
                code_bc = cls[pos + 8 : pos + 8 + code_len]
            pos += alen

        if m_name == "<clinit>":
            continue
        is_static = bool(m_acc & 0x0008)
        if m_name == "main" and "[Ljava/lang/String;" in m_desc:
            lines.extend(["    public static void main(String[] args) {", "    }", ""])
            continue
        ptypes, ret_t = _parse_jvm_params(m_desc, is_static=is_static)
        params_sig = ", ".join(f"{'long' if ty == 'long' else 'int'} p{idx}" for idx, (ty, _) in enumerate(ptypes))
        if m_name == "<init>":
            lines.append(f"    public {cls_simple}({params_sig}) {{")
            lines.extend(_lift_jvm_code(code_bc, ptypes, max_locals, "void", is_static=False))
            lines.extend(["    }", ""])
            continue
        stat_kw = "static " if is_static else ""
        lines.append(f"    public {stat_kw}{ret_t} {re.sub(r'[^A-Za-z0-9_]', '_', m_name)}({params_sig}) {{")
        lines.extend(_lift_jvm_code(code_bc, ptypes, max_locals, ret_t, is_static=is_static))
        lines.extend(["    }", ""])

    lines.append("}")
    return rel_java, "\n".join(lines) + "\n"


def reconstruct_dex_apk_project(
    target_path: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Reconstructs a Gradle/Java Android or JVM project from an APK, DEX, JAR, or .class binary."""
    t_path = Path(target_path).resolve()
    out_root = Path(output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    raw = t_path.read_bytes()

    generated: List[str] = []
    dex_blobs: List[bytes] = []
    class_blobs: List[bytes] = []

    if raw.startswith(b"dex\n"):
        dex_blobs.append(raw)
    elif raw.startswith(b"\xca\xfe\xba\xbe"):
        class_blobs.append(raw)
    elif raw.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(io.BytesIO(raw), "r") as zf:
            for name in zf.namelist():
                if name.endswith(".dex") and "/" not in name:
                    dex_blobs.append(zf.read(name))
                elif name.endswith(".class"):
                    class_blobs.append(zf.read(name))
                elif name == "AndroidManifest.xml":
                    manifest_xml = decode_axml_binary(zf.read(name))
                    m_dest = out_root / "app" / "src" / "main" / "AndroidManifest.xml"
                    m_dest.parent.mkdir(parents=True, exist_ok=True)
                    m_dest.write_text(manifest_xml, encoding="utf-8")
                    generated.append("app/src/main/AndroidManifest.xml")

    if not dex_blobs and not class_blobs:
        return {"schema": SCHEMA, "status": "not_dex_or_apk", "generated_files": generated}

    java_out = out_root / "app" / "src" / "main" / "java"
    java_paths: List[Path] = []
    for db in dex_blobs:
        for rel_j, src_j in _decode_dex_classes_to_java(db).items():
            dest_j = java_out / rel_j
            dest_j.parent.mkdir(parents=True, exist_ok=True)
            dest_j.write_text(src_j, encoding="utf-8")
            generated.append(f"app/src/main/java/{rel_j}")
            java_paths.append(dest_j)
    for cb in class_blobs:
        dec_cls = _decode_jvm_class_to_java(cb)
        if dec_cls:
            rel_j, src_j = dec_cls
            dest_j = java_out / rel_j
            dest_j.parent.mkdir(parents=True, exist_ok=True)
            dest_j.write_text(src_j, encoding="utf-8")
            generated.append(f"app/src/main/java/{rel_j}")
            java_paths.append(dest_j)

    gradle_txt = "\n".join([
        "plugins { id 'java' }",
        "repositories { mavenCentral() }",
        "",
    ])
    (out_root / "build.gradle").write_text(gradle_txt, encoding="utf-8")
    generated.append("build.gradle")

    javac_passed: Optional[bool] = None
    javac_bin = shutil.which("javac")
    if javac_bin and java_paths:
        try:
            cls_dir = out_root / "build" / "classes"
            cls_dir.mkdir(parents=True, exist_ok=True)
            proc = subprocess.run(
                [javac_bin, "-d", str(cls_dir), *(str(p) for p in java_paths[:32])],
                capture_output=True,
                text=True,
                timeout=30,
            )
            javac_passed = (proc.returncode == 0)
        except Exception:
            javac_passed = False

    return {
        "schema": SCHEMA,
        "status": "complete",
        "project_kind": "android_dex_java",
        "classes_reconstructed": len(java_paths),
        "javac_compiled": javac_passed,
        "generated_files": generated,
    }


# ---------------------------------------------------------------------------
# 3. Python .pyc / PyInstaller Bytecode Decompiler & Project Generator
# ---------------------------------------------------------------------------

def decompile_code_object_to_py(code_obj: Any, *, indent: int = 0) -> Tuple[str, Set[str]]:
    """Decompiles a Python 3.x CodeType object via `dis` stack simulation into executable Python source."""
    pad = "    " * indent
    lines: List[str] = []
    imports_found: Set[str] = set()

    def _emit_fn_body(fn_code: Any, fn_indent: int) -> List[str]:
        fpad = "    " * fn_indent
        arg_n = getattr(fn_code, "co_argcount", 0)
        varnames = list(getattr(fn_code, "co_varnames", ()))
        params = ", ".join(varnames[:arg_n])
        out: List[str] = [f"{'    ' * (fn_indent - 1)}def {fn_code.co_name}({params}):"]
        stack: List[str] = []
        insns = list(dis.get_instructions(fn_code))
        target_offsets = {ins.argval for ins in insns if ins.is_jump_target or "JUMP" in ins.opname}
        branch_targets: Dict[int, str] = {}

        for ins in insns:
            if ins.offset in branch_targets:
                fpad = branch_targets.pop(ins.offset)
            op = ins.opname
            if op in ("RESUME", "NOP", "PUSH_NULL", "PRECALL", "KW_NAMES", "CACHE"):
                continue
            elif op in ("LOAD_FAST", "LOAD_FAST_CHECK", "LOAD_DEREF"):
                stack.append(str(ins.argval))
            elif op == "LOAD_FAST_LOAD_FAST" and isinstance(ins.argval, tuple):
                for _vn in ins.argval:
                    stack.append(str(_vn))
            elif op == "STORE_FAST_LOAD_FAST" and isinstance(ins.argval, tuple) and len(ins.argval) == 2 and stack:
                val = stack.pop()
                out.append(f"{fpad}{ins.argval[0]} = {val}")
                stack.append(str(ins.argval[1]))
            elif op == "STORE_FAST_STORE_FAST" and isinstance(ins.argval, tuple) and len(ins.argval) == 2 and len(stack) >= 2:
                v1, v2 = stack.pop(), stack.pop()
                out.append(f"{fpad}{ins.argval[0]} = {v1}")
                out.append(f"{fpad}{ins.argval[1]} = {v2}")
            elif op in ("LOAD_GLOBAL", "LOAD_NAME"):
                nm = str(ins.argval)
                stack.append(nm)
            elif op == "LOAD_CONST":
                stack.append(repr(ins.argval))
            elif op == "LOAD_ATTR" and stack:
                obj = stack.pop()
                stack.append(f"{obj}.{ins.argval}")
            elif op in ("STORE_FAST", "STORE_NAME", "STORE_GLOBAL") and stack:
                val = stack.pop()
                out.append(f"{fpad}{ins.argval} = {val}")
            elif op == "BINARY_OP" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                op_sym = str(ins.argrepr or "+").rstrip("=")
                stack.append(f"({a} {op_sym} {b})")
            elif op.startswith("BINARY_") and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                mp = {
                    "BINARY_ADD": "+", "BINARY_SUBTRACT": "-", "BINARY_MULTIPLY": "*",
                    "BINARY_TRUE_DIVIDE": "/", "BINARY_FLOOR_DIVIDE": "//",
                    "BINARY_MODULO": "%", "BINARY_XOR": "^", "BINARY_AND": "&", "BINARY_OR": "|",
                }
                stack.append(f"({a} {mp.get(op, '+')} {b})")
            elif op == "COMPARE_OP" and len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                cmp_s = str(ins.argrepr or "==").strip()
                if cmp_s.startswith("bool(") and cmp_s.endswith(")"):
                    cmp_s = cmp_s[5:-1].strip()
                stack.append(f"({a} {cmp_s} {b})")
            elif op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE", "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_FORWARD_IF_TRUE") and stack:
                cond_e = stack.pop()
                tgt_off = int(ins.argval or 0)
                neg = "IF_TRUE" in op
                out.append(f"{fpad}if {'not ' if neg else ''}{cond_e}:")
                branch_targets[tgt_off] = fpad
                fpad = fpad + "    "
            elif op in ("JUMP_FORWARD", "JUMP_ABSOLUTE") and isinstance(ins.argval, int):
                tgt_off = int(ins.argval)
                if fpad != "    " * fn_indent:
                    fpad = "    " * fn_indent
                    out.append(f"{fpad}else:")
                    branch_targets[tgt_off] = fpad
                    fpad = fpad + "    "
            elif op == "UNARY_NEGATIVE" and stack:
                stack.append(f"(-{stack.pop()})")
            elif op in ("CALL", "CALL_FUNCTION", "CALL_METHOD"):
                argc = int(ins.argval or 0) if isinstance(ins.argval, int) else 0
                args = [stack.pop() for _ in range(min(argc, len(stack)))][::-1]
                fn_expr = stack.pop() if stack else "unknown_fn"
                stack.append(f"{fn_expr}({', '.join(args)})")
            elif op == "BUILD_LIST":
                argc = int(ins.argval or 0)
                items = [stack.pop() for _ in range(min(argc, len(stack)))][::-1]
                stack.append(f"[{', '.join(items)}]")
            elif op == "BUILD_TUPLE":
                argc = int(ins.argval or 0)
                items = [stack.pop() for _ in range(min(argc, len(stack)))][::-1]
                stack.append(f"({', '.join(items)}{',' if len(items) == 1 else ''})")
            elif op == "IMPORT_NAME":
                mod_n = str(ins.argval)
                imports_found.add(mod_n.split(".", 1)[0])
                # pop level & fromlist if pushed
                if len(stack) >= 2:
                    stack.pop()
                    stack.pop()
                stack.append(mod_n)
            elif op == "RETURN_VALUE":
                rv = stack.pop() if stack else "None"
                out.append(f"{fpad}return {rv}")
            elif op == "RETURN_CONST":
                out.append(f"{fpad}return {repr(ins.argval)}")
            elif op == "POP_TOP" and stack:
                expr = stack.pop()
                if "(" in expr:
                    out.append(f"{fpad}{expr}")

        if len(out) == 1:
            out.append(f"{fpad}pass")
        return out

    # Walk module-level instructions to collect imports, globals, and nested defs
    top_stack: List[str] = []
    for ins in dis.get_instructions(code_obj):
        op = ins.opname
        if op == "LOAD_CONST":
            top_stack.append(ins.argval)
        elif op == "MAKE_FUNCTION":
            # Pop qualified name or code object depending on Python 3.8..3.13
            code_candidate = None
            while top_stack:
                top_item = top_stack.pop()
                if hasattr(top_item, "co_code"):
                    code_candidate = top_item
                    break
            if code_candidate is not None:
                lines.extend(_emit_fn_body(code_candidate, indent + 1))
                lines.append("")
                top_stack.append(f"<fn:{code_candidate.co_name}>")
        elif op == "IMPORT_NAME":
            mod_n = str(ins.argval)
            imports_found.add(mod_n.split(".", 1)[0])
            if len(top_stack) >= 2:
                top_stack.pop()
                top_stack.pop()
            top_stack.append(mod_n)
            lines.append(f"{pad}import {mod_n}")
        elif op in ("STORE_NAME", "STORE_GLOBAL") and top_stack:
            v = top_stack.pop()
            if isinstance(v, str) and v.startswith("<fn:"):
                continue
            lines.append(f"{pad}{ins.argval} = {repr(v)}")

    # Ensure every nested function in co_consts was emitted even if stored differently
    emitted_names = {ln.split("def ", 1)[1].split("(", 1)[0] for ln in lines if ln.lstrip().startswith("def ")}
    for c in getattr(code_obj, "co_consts", ()):
        if hasattr(c, "co_code") and c.co_name not in emitted_names and not c.co_name.startswith("<"):
            lines.extend(_emit_fn_body(c, indent + 1))
            lines.append("")

    return ("\n".join(lines) + "\n") if lines else "# empty module\n", imports_found


def reconstruct_python_project(
    target_path: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Reconstructs a runnable Python project from a `.pyc`, `.pyz`, or PyInstaller executable."""
    t_path = Path(target_path).resolve()
    out_root = Path(output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    raw = t_path.read_bytes()

    generated: List[str] = []
    pyc_files: List[Path] = []
    all_imports: Set[str] = set()

    if len(raw) >= 16 and struct.unpack_from("<HH", raw, 0)[1] == 0x0A0D:
        single_pyc = out_root / f"{t_path.stem}_orig.pyc"
        single_pyc.write_bytes(raw)
        pyc_files.append(single_pyc)
    else:
        from aether_re.unpackers import unpack_container
        unp_dir = out_root / "_unpacked_py"
        unpack_container(t_path, unp_dir)
        pyc_files = sorted(unp_dir.rglob("*.pyc"))

    src_dir = out_root / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    decompiled_count = 0
    for pf in pyc_files:
        b = pf.read_bytes()
        if len(b) <= 16:
            continue
        try:
            co = marshal.loads(b[16:])
        except Exception:
            continue
        if not hasattr(co, "co_code"):
            continue
        py_src, imps = decompile_code_object_to_py(co)
        all_imports.update(imps)
        stem = t_path.stem if pf.name.endswith("_orig.pyc") else pf.stem
        out_py = src_dir / f"{stem}.py"
        out_py.write_text(py_src, encoding="utf-8")
        generated.append(f"src/{out_py.name}")
        decompiled_count += 1

    stdlib_skip = {"sys", "os", "math", "json", "re", "typing", "pathlib", "struct", "zlib", "builtins"}
    reqs = sorted(all_imports - stdlib_skip)
    (out_root / "requirements.txt").write_text("\n".join(reqs) + ("\n" if reqs else ""), encoding="utf-8")
    (out_root / "pyproject.toml").write_text(
        f'[project]\nname = "{re.sub(r"[^A-Za-z0-9_-]", "-", t_path.stem.lower())}"\nversion = "0.1.0"\nrequires-python = ">=3.10"\ndependencies = {json.dumps(reqs)}\n',
        encoding="utf-8",
    )
    generated.extend(["requirements.txt", "pyproject.toml"])

    return {
        "schema": SCHEMA,
        "status": "complete" if decompiled_count > 0 else "partial",
        "project_kind": "python_bytecode_project",
        "decompiled_modules": decompiled_count,
        "dependencies": reqs,
        "generated_files": generated,
    }


# ---------------------------------------------------------------------------
# 4. WebAssembly (.wasm) -> C99 + WASI Shim Reconstructor
# ---------------------------------------------------------------------------

def _read_sleb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    size = 64
    b = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
    if shift < size and (b & 0x40):
        result |= -(1 << shift)
    return result, pos


def reconstruct_wasm_project(
    target_path: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Decodes WebAssembly binary sections (Type, Import, Function, Global, Export, Code, Data) into compilable C99 + CMake."""
    t_path = Path(target_path).resolve()
    out_root = Path(output_dir).resolve()
    raw = t_path.read_bytes()
    if len(raw) < 8 or not raw.startswith(WASM_MAGIC):
        return {"schema": SCHEMA, "status": "not_wasm", "generated_files": []}

    report = analyze_wasm_bytes(raw, str(t_path))
    pos = 8
    types_sig: List[Tuple[List[int], List[int]]] = []
    func_type_indices: List[int] = []
    imported_funcs = 0
    globals_init: List[int] = []
    exports_map: Dict[int, str] = {}
    code_bodies: List[bytes] = []
    data_segments: List[Tuple[int, bytes]] = []

    def _read_const_expr(buf: bytes, idx: int) -> Tuple[int, int]:
        val = 0
        while idx < len(buf):
            op_c = buf[idx]
            idx += 1
            if op_c == 0x0B:
                break
            if op_c in (0x41, 0x42):
                val, idx = _read_sleb128(buf, idx)
            elif op_c == 0x23:
                _gi, idx = _read_uleb128(buf, idx)
            elif op_c == 0x43 and idx + 4 <= len(buf):
                idx += 4
            elif op_c == 0x44 and idx + 8 <= len(buf):
                idx += 8
        return val, idx

    while pos < len(raw):
        sec_id = raw[pos]
        pos += 1
        sec_sz, pos = _read_uleb128(raw, pos)
        sec_end = min(pos + sec_sz, len(raw))
        sec = raw[pos:sec_end]
        p = 0
        if sec_id == 1:  # Type
            cnt, p = _read_uleb128(sec, p)
            for _ in range(cnt):
                _form = sec[p]
                p += 1
                np, p = _read_uleb128(sec, p)
                ptypes = list(sec[p : p + np])
                p += np
                nr, p = _read_uleb128(sec, p)
                rtypes = list(sec[p : p + nr])
                p += nr
                types_sig.append((ptypes, rtypes))
        elif sec_id == 2:  # Import
            cnt, p = _read_uleb128(sec, p)
            for _ in range(cnt):
                _, p = _read_wasm_string(sec, p)
                _, p = _read_wasm_string(sec, p)
                kind = sec[p]
                p += 1
                if kind == 0:
                    imported_funcs += 1
                    _, p = _read_uleb128(sec, p)
                elif kind == 1:
                    p += 1
                    flg = sec[p]
                    p += 1
                    _, p = _read_uleb128(sec, p)
                    if flg & 1:
                        _, p = _read_uleb128(sec, p)
                elif kind in (2, 3):
                    flg = sec[p]
                    p += 1
                    _, p = _read_uleb128(sec, p)
                    if kind == 2 and (flg & 1):
                        _, p = _read_uleb128(sec, p)
                    elif kind == 3:
                        p += 1
        elif sec_id == 3:  # Function
            cnt, p = _read_uleb128(sec, p)
            for _ in range(cnt):
                ti, p = _read_uleb128(sec, p)
                func_type_indices.append(ti)
        elif sec_id == 6:  # Global
            cnt, p = _read_uleb128(sec, p)
            for _ in range(cnt):
                if p + 2 > len(sec):
                    break
                _vt, _mut = sec[p], sec[p + 1]
                p += 2
                g_val, p = _read_const_expr(sec, p)
                globals_init.append(int(g_val))
        elif sec_id == 7:  # Export
            cnt, p = _read_uleb128(sec, p)
            for _ in range(cnt):
                nm, p = _read_wasm_string(sec, p)
                kind = sec[p]
                p += 1
                idx, p = _read_uleb128(sec, p)
                if kind == 0:
                    exports_map[idx] = nm
        elif sec_id == 10:  # Code
            cnt, p = _read_uleb128(sec, p)
            for _ in range(cnt):
                bsz, p = _read_uleb128(sec, p)
                code_bodies.append(sec[p : p + bsz])
                p += bsz
        elif sec_id == 11:  # Data
            cnt, p = _read_uleb128(sec, p)
            for _ in range(cnt):
                mode, p = _read_uleb128(sec, p)
                if mode == 0:
                    off_v, p = _read_const_expr(sec, p)
                    dsz, p = _read_uleb128(sec, p)
                    data_segments.append((int(off_v), sec[p : p + dsz]))
                    p += dsz
                elif mode == 1:
                    dsz, p = _read_uleb128(sec, p)
                    p += dsz
                elif mode == 2:
                    _midx, p = _read_uleb128(sec, p)
                    off_v, p = _read_const_expr(sec, p)
                    dsz, p = _read_uleb128(sec, p)
                    data_segments.append((int(off_v), sec[p : p + dsz]))
                    p += dsz
        pos = sec_end

    src_dir = out_root / "src"
    inc_dir = out_root / "include"
    src_dir.mkdir(parents=True, exist_ok=True)
    inc_dir.mkdir(parents=True, exist_ok=True)

    c_lines = [
        "/* Auto-Lifted WebAssembly -> C99 Project by AetherRE Megazord v8.2 */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        "#ifdef _WIN32",
        "#define W2C_EXP __declspec(dllexport)",
        "#else",
        "#define W2C_EXP",
        "#endif",
        "static uint8_t wasm_mem[65536];",
        f"static int64_t wasm_globals[{max(1, len(globals_init))}] = {{"
        + (", ".join(f"{g}LL" for g in globals_init) if globals_init else "0LL")
        + "};",
        "static int _wasm_mem_inited = 0;",
        "static void _wasm_init_mem(void) {",
        "    if (_wasm_mem_inited) return;",
        "    _wasm_mem_inited = 1;",
    ]
    for seg_i, (seg_off, seg_bytes) in enumerate(data_segments):
        if seg_bytes and 0 <= seg_off < 65536:
            bounded = seg_bytes[: 65536 - seg_off]
            hex_arr = ", ".join(f"0x{b:02x}" for b in bounded)
            c_lines.append(f"    static const uint8_t _seg_{seg_i}[{len(bounded)}] = {{{hex_arr}}};")
            c_lines.append(f"    memcpy(wasm_mem + {seg_off}U, _seg_{seg_i}, sizeof(_seg_{seg_i}));")
    c_lines.extend(["}", ""])
    def_lines = ["LIBRARY wasm_reconstructed", "EXPORTS"]

    # Emit forward declarations so intra-module WASM `call` works seamlessly
    for local_idx in range(len(code_bodies)):
        g_idx = imported_funcs + local_idx
        t_idx = func_type_indices[local_idx] if local_idx < len(func_type_indices) else 0
        ptypes, _rtypes = types_sig[t_idx] if t_idx < len(types_sig) else ([], [])
        raw_nm = exports_map.get(g_idx, f"wasm_func_{g_idx}")
        c_nm = re.sub(r"[^A-Za-z0-9_]", "_", raw_nm)
        params = ", ".join(f"int64_t l{i}" for i in range(len(ptypes))) or "void"
        c_lines.append(f"W2C_EXP int64_t {c_nm}({params});")
    c_lines.append("")

    lifted_fns = 0
    for local_idx, body in enumerate(code_bodies):
        global_idx = imported_funcs + local_idx
        t_idx = func_type_indices[local_idx] if local_idx < len(func_type_indices) else 0
        ptypes, rtypes = types_sig[t_idx] if t_idx < len(types_sig) else ([], [])
        raw_nm = exports_map.get(global_idx, f"wasm_func_{global_idx}")
        c_nm = re.sub(r"[^A-Za-z0-9_]", "_", raw_nm)
        params = ", ".join(f"int64_t l{i}" for i in range(len(ptypes))) or "void"
        c_lines.append(f"W2C_EXP int64_t {c_nm}({params}) {{")
        c_lines.append("    _wasm_init_mem();")

        bp = 0
        n_loc_groups, bp = _read_uleb128(body, bp)
        extra_locals = 0
        for _ in range(n_loc_groups):
            lcnt, bp = _read_uleb128(body, bp)
            bp += 1  # valtype
            extra_locals += lcnt
        for li in range(len(ptypes), len(ptypes) + extra_locals):
            c_lines.append(f"    int64_t l{li} = 0;")

        stack: List[str] = []
        # (kind, branch_target_lbl, end_lbl, res_var_or_none)
        ctrl_stack: List[Tuple[str, str, str, Optional[str]]] = []
        blk_seq = 0
        while bp < len(body):
            op = body[bp]
            bp += 1
            if op == 0x0B:  # end
                if not ctrl_stack:
                    break
                kind, _br_lbl, end_lbl, res_var = ctrl_stack.pop()
                if res_var is not None and stack:
                    c_lines.append(f"    {res_var} = {stack.pop()};")
                if kind in ("if", "else"):
                    c_lines.append("    }")
                c_lines.append(f"{end_lbl}:;")
                if res_var is not None:
                    stack.append(res_var)
            elif op == 0x02:  # block
                bt, bp = _read_sleb128(body, bp)
                blk_seq += 1
                end_lbl = f"_wb_{local_idx}_{blk_seq}_end"
                res_var = None
                if bt != -64:
                    res_var = f"_bres_{local_idx}_{blk_seq}"
                    c_lines.append(f"    int64_t {res_var} = 0;")
                ctrl_stack.append(("block", end_lbl, end_lbl, res_var))
            elif op == 0x03:  # loop
                _bt, bp = _read_sleb128(body, bp)
                blk_seq += 1
                start_lbl = f"_wb_{local_idx}_{blk_seq}_start"
                end_lbl = f"_wb_{local_idx}_{blk_seq}_end"
                c_lines.append(f"{start_lbl}:;")
                ctrl_stack.append(("loop", start_lbl, end_lbl, None))
            elif op == 0x04:  # if
                bt, bp = _read_sleb128(body, bp)
                cond = stack.pop() if stack else "0"
                blk_seq += 1
                end_lbl = f"_wb_{local_idx}_{blk_seq}_end"
                res_var = None
                if bt != -64:
                    res_var = f"_bres_{local_idx}_{blk_seq}"
                    c_lines.append(f"    int64_t {res_var} = 0;")
                ctrl_stack.append(("if", end_lbl, end_lbl, res_var))
                c_lines.append(f"    if ({cond}) {{")
            elif op == 0x05:  # else
                if ctrl_stack and ctrl_stack[-1][0] == "if":
                    _k, br_lbl, end_lbl, res_var = ctrl_stack[-1]
                    if res_var is not None and stack:
                        c_lines.append(f"    {res_var} = {stack.pop()};")
                    ctrl_stack[-1] = ("else", br_lbl, end_lbl, res_var)
                    c_lines.append("    } else {")
            elif op == 0x0C:  # br
                depth, bp = _read_uleb128(body, bp)
                if 0 <= depth < len(ctrl_stack):
                    tgt_entry = ctrl_stack[-1 - depth]
                    if tgt_entry[3] is not None and stack:
                        c_lines.append(f"    {tgt_entry[3]} = {stack.pop()};")
                    c_lines.append(f"    goto {tgt_entry[1]};")
                else:
                    rv = stack.pop() if (stack and rtypes) else "0LL"
                    c_lines.append(f"    return {rv};")
            elif op == 0x0D:  # br_if
                depth, bp = _read_uleb128(body, bp)
                cond = stack.pop() if stack else "0"
                if 0 <= depth < len(ctrl_stack):
                    tgt_entry = ctrl_stack[-1 - depth]
                    c_lines.append(f"    if ({cond}) goto {tgt_entry[1]};")
                else:
                    rv = stack.pop() if (stack and rtypes) else "0LL"
                    c_lines.append(f"    if ({cond}) return {rv};")
            elif op == 0x10:  # call
                f_idx, bp = _read_uleb128(body, bp)
                loc_f = f_idx - imported_funcs
                ft_idx = func_type_indices[loc_f] if 0 <= loc_f < len(func_type_indices) else 0
                f_ptypes, _f_rtypes = types_sig[ft_idx] if ft_idx < len(types_sig) else ([], [])
                call_args = [stack.pop() for _ in range(min(len(f_ptypes), len(stack)))][::-1]
                tgt_nm = re.sub(r"[^A-Za-z0-9_]", "_", exports_map.get(f_idx, f"wasm_func_{f_idx}"))
                stack.append(f"{tgt_nm}({', '.join(call_args)})")
            elif op == 0x1A:  # drop
                if stack:
                    stack.pop()
            elif op == 0x1B:  # select
                c_sel = stack.pop() if stack else "0"
                v2_sel = stack.pop() if stack else "0"
                v1_sel = stack.pop() if stack else "0"
                stack.append(f"(({c_sel}) ? ({v1_sel}) : ({v2_sel}))")
            elif op == 0x20:  # local.get
                li, bp = _read_uleb128(body, bp)
                stack.append(f"l{li}")
            elif op == 0x21:  # local.set
                li, bp = _read_uleb128(body, bp)
                val = stack.pop() if stack else "0"
                c_lines.append(f"    l{li} = {val};")
            elif op == 0x22:  # local.tee
                li, bp = _read_uleb128(body, bp)
                val = stack.pop() if stack else "0"
                c_lines.append(f"    l{li} = {val};")
                stack.append(f"l{li}")
            elif op == 0x23:  # global.get
                gi, bp = _read_uleb128(body, bp)
                safe_gi = gi if 0 <= gi < max(1, len(globals_init)) else 0
                stack.append(f"wasm_globals[{safe_gi}]")
            elif op == 0x24:  # global.set
                gi, bp = _read_uleb128(body, bp)
                val = stack.pop() if stack else "0"
                safe_gi = gi if 0 <= gi < max(1, len(globals_init)) else 0
                c_lines.append(f"    wasm_globals[{safe_gi}] = {val};")
            elif op == 0x28:  # i32.load
                _fl, bp = _read_uleb128(body, bp)
                off_m, bp = _read_uleb128(body, bp)
                base_a = stack.pop() if stack else "0"
                stack.append(f"((int64_t)(*(const int32_t*)(wasm_mem + (((uint32_t)({base_a}) + {off_m}U) & 0xFFFCU))))")
            elif op in (0x2C, 0x2D):  # i32.load8_s / i32.load8_u
                _fl, bp = _read_uleb128(body, bp)
                off_m, bp = _read_uleb128(body, bp)
                base_a = stack.pop() if stack else "0"
                cast8 = "int8_t" if op == 0x2C else "uint8_t"
                stack.append(f"((int64_t)(*({cast8}*)(wasm_mem + (((uint32_t)({base_a}) + {off_m}U) & 0xFFFFU))))")
            elif op == 0x36:  # i32.store
                _fl, bp = _read_uleb128(body, bp)
                off_m, bp = _read_uleb128(body, bp)
                val_s = stack.pop() if stack else "0"
                base_a = stack.pop() if stack else "0"
                c_lines.append(f"    *(int32_t*)(wasm_mem + (((uint32_t)({base_a}) + {off_m}U) & 0xFFFCU)) = (int32_t)({val_s});")
            elif op == 0x3A:  # i32.store8
                _fl, bp = _read_uleb128(body, bp)
                off_m, bp = _read_uleb128(body, bp)
                val_s = stack.pop() if stack else "0"
                base_a = stack.pop() if stack else "0"
                c_lines.append(f"    wasm_mem[(((uint32_t)({base_a}) + {off_m}U) & 0xFFFFU)] = (uint8_t)({val_s});")
            elif op == 0x41:  # i32.const
                iv, bp = _read_sleb128(body, bp)
                stack.append(f"((int64_t)(int32_t)({iv}))")
            elif op == 0x42:  # i64.const
                iv, bp = _read_sleb128(body, bp)
                stack.append(f"((int64_t)({iv}LL))")
            elif op == 0x45 and stack:  # i32.eqz
                a_e = stack.pop()
                stack.append(f"((int64_t)((int32_t)({a_e}) == 0 ? 1 : 0))")
            elif op in (0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F) and len(stack) >= 2:
                b_e, a_e = stack.pop(), stack.pop()
                cmp_tbl = {
                    0x46: ("int32_t", "=="), 0x47: ("int32_t", "!="),
                    0x48: ("int32_t", "<"), 0x49: ("uint32_t", "<"),
                    0x4A: ("int32_t", ">"), 0x4B: ("uint32_t", ">"),
                    0x4C: ("int32_t", "<="), 0x4D: ("uint32_t", "<="),
                    0x4E: ("int32_t", ">="), 0x4F: ("uint32_t", ">="),
                }
                cty, cmp_op = cmp_tbl[op]
                stack.append(f"((int64_t)(({cty})({a_e}) {cmp_op} ({cty})({b_e}) ? 1 : 0))")
            elif op in (
                0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
                0x7C, 0x7D, 0x7E, 0x83, 0x84, 0x85,
            ) and len(stack) >= 2:
                b_e, a_e = stack.pop(), stack.pop()
                op_c = {
                    0x6A: "+", 0x6B: "-", 0x6C: "*", 0x6D: "/", 0x6E: "/", 0x6F: "%", 0x70: "%",
                    0x71: "&", 0x72: "|", 0x73: "^", 0x74: "<<", 0x75: ">>", 0x76: ">>",
                    0x7C: "+", 0x7D: "-", 0x7E: "*", 0x83: "&", 0x84: "|", 0x85: "^",
                }[op]
                if op in (0x6E, 0x70, 0x76):
                    stack.append(f"((int64_t)(int32_t)((uint32_t)({a_e}) {op_c} (uint32_t)({b_e})))")
                elif op <= 0x75:
                    stack.append(f"((int64_t)(int32_t)((int32_t)({a_e}) {op_c} (int32_t)({b_e})))")
                else:
                    stack.append(f"((int64_t)(({a_e}) {op_c} ({b_e})))")
            elif op == 0x0F:  # return
                rv = stack.pop() if stack else "0LL"
                c_lines.append(f"    return {rv};")

        ret_expr = stack.pop() if (stack and rtypes) else "0LL"
        c_lines.append(f"    return {ret_expr};")
        c_lines.append("}")
        c_lines.append("")
        if global_idx in exports_map:
            def_lines.append(f"    {c_nm}")
        lifted_fns += 1

    (src_dir / "wasm_module.c").write_text("\n".join(c_lines), encoding="utf-8")
    (src_dir / "exports.def").write_text("\n".join(def_lines) + "\n", encoding="utf-8")
    (out_root / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\nproject(wasm_reconstructed LANGUAGES C)\nadd_library(wasm_reconstructed SHARED src/wasm_module.c src/exports.def)\n",
        encoding="utf-8",
    )

    return {
        "schema": SCHEMA,
        "status": "complete",
        "project_kind": "wasm_native_c",
        "functions_lifted": lifted_fns,
        "globals_count": len(globals_init),
        "data_segments_count": len(data_segments),
        "exports": list(exports_map.values()),
        "wasi_capabilities": report.wasi_capabilities,
        "generated_files": ["src/wasm_module.c", "src/exports.def", "CMakeLists.txt"],
    }


# ---------------------------------------------------------------------------
# 5. JavaScript / Webpack Bundle -> TypeScript/ESM Project Reconstructor
# ---------------------------------------------------------------------------

_JS_MOD_HEAD_RE = re.compile(
    r'(["\']?[A-Za-z0-9_./@-]+["\']?)\s*(?::\s*(?:function\s*\(([^(){}\n]*)\)|\(([^(){}\n]*)\)\s*=>|([A-Za-z_$][\w$]*)\s*=>)|\(([^(){}\n]*)\))\s*\{'
)


def _scan_balanced_braces(src: str, open_idx: int) -> Optional[int]:
    """Finds the matching closing `}` for `src[open_idx] == '{'`, skipping strings, templates, and comments."""
    if open_idx >= len(src) or src[open_idx] != "{":
        return None
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        ch = src[i]
        if ch in ("'", '"', "`"):
            q = ch
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "/":
                nl = src.find("\n", i + 2)
                i = n if nl == -1 else nl + 1
                continue
            if nxt == "*":
                end_c = src.find("*/", i + 2)
                i = n if end_c == -1 else end_c + 2
                continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _extract_js_bundle_modules(js_text: str) -> List[Tuple[str, str, str]]:
    """Extracts nested Webpack/ESBuild/CJS module bodies with arbitrary brace nesting."""
    results: List[Tuple[str, str, str]] = []
    pos = 0
    n = len(js_text)
    while pos < n and len(results) < 250:
        m = _JS_MOD_HEAD_RE.search(js_text, pos)
        if not m:
            break
        key_raw = m.group(1).strip("\"'")
        # Skip control keywords that look like `if (...) {` or `while (...) {`
        if key_raw in ("if", "else", "for", "while", "switch", "catch", "with", "function", "constructor", "__commonJS", "__esm"):
            pos = m.end()
            continue
        brace_idx = m.end() - 1
        end_idx = _scan_balanced_braces(js_text, brace_idx)
        if end_idx is None:
            pos = m.end()
            continue
        params = next((g for g in (m.group(2), m.group(3), m.group(4), m.group(5)) if g is not None), "")
        body = js_text[brace_idx + 1 : end_idx]
        # Avoid consuming an outer wrapper dictionary (`var mods = { alpha: ... }`) as a single module
        if ":" in key_raw or key_raw.isidentifier() or key_raw.isdigit() or "/" in key_raw or "." in key_raw:
            results.append((key_raw, params.strip(), body))
        pos = end_idx + 1
    return results


def reconstruct_js_bundle_project(
    target_path: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    """Unbundles Webpack/ESBuild/CJS JS into clean modules + TypeScript interfaces + package.json."""
    t_path = Path(target_path).resolve()
    out_root = Path(output_dir).resolve()
    mod_dir = out_root / "src" / "modules"
    mod_dir.mkdir(parents=True, exist_ok=True)
    js_text = t_path.read_text(encoding="utf-8", errors="replace")

    generated: List[str] = []
    modules_extracted = 0

    wb_text = ""
    # Try WebcrackBridge first if webcrack deps are available
    try:
        from aether_re.webcrack_bridge import WebcrackBridge
        wb = WebcrackBridge()
        w_res = wb.deobfuscate(t_path, output_dir=mod_dir, timeout_seconds=30)
        if w_res.success and w_res.deobfuscated_code:
            wb_text = w_res.deobfuscated_code
            (out_root / "src" / "index.js").write_text(wb_text, encoding="utf-8")
            generated.append("src/index.js")
            modules_extracted = max(1, w_res.module_count)
    except Exception:
        pass

    # Lexical balanced-brace Webpack/ESBuild/CJS module splitter + semantic deobfuscator
    source_for_split = wb_text or js_text
    extracted_mods = _extract_js_bundle_modules(source_for_split)
    if extracted_mods:
        barrel_exports: List[str] = []
        seen_keys: Set[str] = set()
        ts_count = 0
        for idx_m, (m_key, m_params, m_body) in enumerate(extracted_mods[:200]):
            clean_key = re.sub(r"[^A-Za-z0-9_]", "_", m_key) or f"mod_{idx_m}"
            if clean_key[0].isdigit():
                clean_key = f"mod_{clean_key}"
            if clean_key in seen_keys:
                clean_key = f"{clean_key}_{idx_m}"
            seen_keys.add(clean_key)
            sig_p = ", ".join(p.strip() for p in m_params.split(",") if p.strip()) if m_params else ""
            wrapped = f"export function module_{clean_key}({sig_p}) {{\n{m_body}\n}}"
            deob = deobfuscate_javascript_snippet(wrapped)
            m_file = mod_dir / f"{clean_key}.ts"
            m_file.write_text(
                deob["deobfuscated_code"] + "\n" + "\n".join(deob.get("typescript_interfaces", [])),
                encoding="utf-8",
            )
            generated.append(f"src/modules/{m_file.name}")
            barrel_exports.append(f'export * from "./modules/{clean_key}.js";')
            ts_count += 1
        (out_root / "src" / "index.ts").write_text("\n".join(barrel_exports) + "\n", encoding="utf-8")
        generated.append("src/index.ts")
        modules_extracted = max(modules_extracted, ts_count)
    elif modules_extracted == 0:
        deob = deobfuscate_javascript_snippet(js_text)
        idx_p = out_root / "src" / "index.ts"
        idx_p.write_text(deob["deobfuscated_code"] + "\n" + "\n".join(deob.get("typescript_interfaces", [])), encoding="utf-8")
        generated.append("src/index.ts")
        modules_extracted = 1

    (out_root / "package.json").write_text(
        json.dumps(
            {
                "name": re.sub(r"[^a-z0-9-]", "-", t_path.stem.lower()) or "reconstructed-js-app",
                "version": "1.0.0",
                "type": "module",
                "main": "src/index.js" if "src/index.js" in generated else "src/index.ts",
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    (out_root / "tsconfig.json").write_text(
        json.dumps({"compilerOptions": {"target": "ES2022", "module": "ESNext", "strict": False}}, indent=2) + "\n",
        encoding="utf-8",
    )
    generated.extend(["package.json", "tsconfig.json"])

    return {
        "schema": SCHEMA,
        "status": "complete",
        "project_kind": "javascript_webpack_ts",
        "modules_extracted": modules_extracted,
        "generated_files": generated,
    }
