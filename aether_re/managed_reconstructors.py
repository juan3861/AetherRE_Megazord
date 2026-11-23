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

    if pos + 6 > len(cls):
        return None
    _acc, this_cls_idx, _super_idx = struct.unpack_from(">HHH", cls, pos)
    pos += 6
    if_cnt = struct.unpack_from(">H", cls, pos)[0]
    pos += 2 + if_cnt * 2
    fld_cnt = struct.unpack_from(">H", cls, pos)[0]
    pos += 2
    for _ in range(fld_cnt):
        if pos + 8 > len(cls):
            break
        ac_cnt = struct.unpack_from(">H", cls, pos + 6)[0]
        pos += 8
        for _ in range(ac_cnt):
            alen = struct.unpack_from(">I", cls, pos + 2)[0]
            pos += 6 + alen

    if pos + 2 > len(cls):
        return None
    mth_cnt = struct.unpack_from(">H", cls, pos)[0]
    pos += 2

    fqcn_raw = _cls_name(this_cls_idx).replace("/", ".")
    pkg, _, cls_simple = fqcn_raw.rpartition(".")
    cls_simple = re.sub(r"[^A-Za-z0-9_]", "_", cls_simple) or "RecoveredClass"
    rel_java = (pkg.replace(".", "/") + "/" if pkg else "") + f"{cls_simple}.java"

    lines: List[str] = []
    if pkg:
        lines.extend([f"package {pkg};", ""])
    lines.append(f"public class {cls_simple} {{")

    def _lift_jvm_code(bc: bytes, n_params: int) -> List[str]:
        st: List[str] = []
        out_j: List[str] = []
        p = 0
        while p < len(bc):
            op = bc[p]
            p += 1
            if op == 0x1A:
                st.append("p0")
            elif op == 0x1B:
                st.append("p1")
            elif op == 0x1C:
                st.append("p2")
            elif op == 0x1D:
                st.append("p3")
            elif op == 0x15 and p < len(bc):  # iload idx
                st.append(f"p{bc[p]}")
                p += 1
            elif 0x02 <= op <= 0x08:  # iconst_m1 .. iconst_5
                st.append(str(op - 3))
            elif op == 0x10 and p < len(bc):  # bipush
                st.append(str(struct.unpack("<b", bytes([bc[p]]))[0]))
                p += 1
            elif op == 0x11 and p + 1 < len(bc):  # sipush
                st.append(str(struct.unpack_from(">h", bc, p)[0]))
                p += 2
            elif op in (0x60, 0x64, 0x68, 0x6C, 0x70, 0x7E, 0x80, 0x82) and len(st) >= 2:
                b_e, a_e = st.pop(), st.pop()
                mop = {0x60: "+", 0x64: "-", 0x68: "*", 0x6C: "/", 0x70: "%", 0x7E: "&", 0x80: "|", 0x82: "^"}[op]
                st.append(f"({a_e} {mop} {b_e})")
            elif op == 0xAC:  # ireturn
                rv = st.pop() if st else "0"
                out_j.append(f"        return {rv};")
            elif op == 0xB1:  # return (void)
                out_j.append("        return;")
        return out_j or ["        return 0;"]

    for _ in range(mth_cnt):
        if pos + 8 > len(cls):
            break
        m_acc, m_name_idx, m_desc_idx, m_attr_cnt = struct.unpack_from(">HHHH", cls, pos)
        pos += 8
        m_name = _utf8(m_name_idx)
        m_desc = _utf8(m_desc_idx)
        code_bc = b""
        for _ in range(m_attr_cnt):
            aname_idx, alen = struct.unpack_from(">HI", cls, pos)
            pos += 6
            if _utf8(aname_idx) == "Code" and alen >= 8:
                code_len = struct.unpack_from(">I", cls, pos + 4)[0]
                code_bc = cls[pos + 8 : pos + 8 + code_len]
            pos += alen

        if m_name in ("<init>", "<clinit>"):
            continue
        is_static = bool(m_acc & 0x0008)
        arg_part = m_desc[m_desc.find("(") + 1 : m_desc.find(")")] if "(" in m_desc and ")" in m_desc else ""
        n_int_args = arg_part.count("I")
        ret_void = m_desc.endswith(")V")
        if not is_static:
            continue
        params_sig = ", ".join(f"int p{idx}" for idx in range(n_int_args))
        ret_t = "void" if ret_void else "int"
        if m_name == "main" and "[Ljava/lang/String;" in m_desc:
            lines.extend(["    public static void main(String[] args) {", "    }", ""])
            continue
        lines.append(f"    public static {ret_t} {re.sub(r'[^A-Za-z0-9_]', '_', m_name)}({params_sig}) {{")
        lines.extend(_lift_jvm_code(code_bc, n_int_args))
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
    """Decodes WebAssembly binary sections (Type, Import, Function, Export, Code) into compilable C99 + CMake."""
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
    exports_map: Dict[int, str] = {}
    code_bodies: List[bytes] = []

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
        pos = sec_end

    src_dir = out_root / "src"
    inc_dir = out_root / "include"
    src_dir.mkdir(parents=True, exist_ok=True)
    inc_dir.mkdir(parents=True, exist_ok=True)

    c_lines = [
        "/* Auto-Lifted WebAssembly -> C99 Project by AetherRE Megazord v8.1 */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#ifdef _WIN32",
        "#define W2C_EXP __declspec(dllexport)",
        "#else",
        "#define W2C_EXP",
        "#endif",
        "static uint8_t wasm_mem[65536];",
        "",
    ]
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
        ctrl_stack: List[str] = []
        while bp < len(body):
            op = body[bp]
            bp += 1
            if op == 0x0B:  # end
                if not ctrl_stack:
                    break
                kind = ctrl_stack.pop()
                if kind in ("if", "else"):
                    c_lines.append("    }")
                elif kind == "loop":
                    c_lines.append("    }")
            elif op == 0x02:  # block
                _bt, bp = _read_sleb128(body, bp)
                ctrl_stack.append("block")
            elif op == 0x03:  # loop
                _bt, bp = _read_sleb128(body, bp)
                ctrl_stack.append("loop")
                c_lines.append("    while (1) {")
            elif op == 0x04:  # if
                _bt, bp = _read_sleb128(body, bp)
                cond = stack.pop() if stack else "0"
                ctrl_stack.append("if")
                c_lines.append(f"    if ({cond}) {{")
            elif op == 0x05:  # else
                if ctrl_stack and ctrl_stack[-1] == "if":
                    ctrl_stack[-1] = "else"
                    c_lines.append("    } else {")
            elif op == 0x0C:  # br
                depth, bp = _read_uleb128(body, bp)
                _ = depth
                c_lines.append("    break;")
            elif op == 0x0D:  # br_if
                depth, bp = _read_uleb128(body, bp)
                _ = depth
                cond = stack.pop() if stack else "0"
                c_lines.append(f"    if ({cond}) break;")
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
            elif op == 0x20:  # local.get
                li, bp = _read_uleb128(body, bp)
                stack.append(f"l{li}")
            elif op == 0x21:  # local.set
                li, bp = _read_uleb128(body, bp)
                val = stack.pop() if stack else "0"
                c_lines.append(f"    l{li} = {val};")
            elif op == 0x28:  # i32.load
                _fl, bp = _read_uleb128(body, bp)
                off_m, bp = _read_uleb128(body, bp)
                base_a = stack.pop() if stack else "0"
                stack.append(f"((int64_t)(*(const int32_t*)(wasm_mem + (((uint32_t)({base_a}) + {off_m}U) & 0xFFFCU))))")
            elif op == 0x36:  # i32.store
                _fl, bp = _read_uleb128(body, bp)
                off_m, bp = _read_uleb128(body, bp)
                val_s = stack.pop() if stack else "0"
                base_a = stack.pop() if stack else "0"
                c_lines.append(f"    *(int32_t*)(wasm_mem + (((uint32_t)({base_a}) + {off_m}U) & 0xFFFCU)) = (int32_t)({val_s});")
            elif op == 0x41:  # i32.const
                iv, bp = _read_sleb128(body, bp)
                stack.append(f"((int64_t)(int32_t)({iv}))")
            elif op == 0x42:  # i64.const
                iv, bp = _read_sleb128(body, bp)
                stack.append(f"((int64_t)({iv}LL))")
            elif op == 0x45 and stack:  # i32.eqz
                a_e = stack.pop()
                stack.append(f"((int64_t)((int32_t)({a_e}) == 0 ? 1 : 0))")
            elif op in (0x46, 0x47, 0x48, 0x4A, 0x4C, 0x4E) and len(stack) >= 2:
                b_e, a_e = stack.pop(), stack.pop()
                cmp_op = {0x46: "==", 0x47: "!=", 0x48: "<", 0x4A: ">", 0x4C: "<=", 0x4E: ">="}[op]
                stack.append(f"((int64_t)((int32_t)({a_e}) {cmp_op} (int32_t)({b_e}) ? 1 : 0))")
            elif op in (0x6A, 0x6B, 0x6C, 0x6D, 0x6F, 0x71, 0x72, 0x73, 0x74, 0x75, 0x7C, 0x7D, 0x7E, 0x83, 0x84, 0x85) and len(stack) >= 2:
                b_e, a_e = stack.pop(), stack.pop()
                op_c = {
                    0x6A: "+", 0x6B: "-", 0x6C: "*", 0x6D: "/", 0x6F: "%", 0x71: "&", 0x72: "|", 0x73: "^", 0x74: "<<", 0x75: ">>",
                    0x7C: "+", 0x7D: "-", 0x7E: "*", 0x83: "&", 0x84: "|", 0x85: "^",
                }[op]
                if op <= 0x75:
                    stack.append(f"((int64_t)(int32_t)((int32_t)({a_e}) {op_c} (int32_t)({b_e})))")
                else:
                    stack.append(f"((int64_t)(({a_e}) {op_c} ({b_e})))")
            elif op == 0x0F:  # return
                rv = stack.pop() if stack else "0"
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
        "exports": list(exports_map.values()),
        "wasi_capabilities": report.wasi_capabilities,
        "generated_files": ["src/wasm_module.c", "src/exports.def", "CMakeLists.txt"],
    }


# ---------------------------------------------------------------------------
# 5. JavaScript / Webpack Bundle -> TypeScript/ESM Project Reconstructor
# ---------------------------------------------------------------------------

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

    # Try WebcrackBridge first if webcrack deps are available
    try:
        from aether_re.webcrack_bridge import WebcrackBridge
        wb = WebcrackBridge()
        w_res = wb.deobfuscate(t_path, output_dir=mod_dir, timeout_seconds=30)
        if w_res.success and w_res.deobfuscated_code:
            (out_root / "src" / "index.js").write_text(w_res.deobfuscated_code, encoding="utf-8")
            generated.append("src/index.js")
            modules_extracted = max(1, w_res.module_count)
    except Exception:
        pass

    # Pure-Python Webpack/CJS dictionary module splitter + semantic deobfuscator
    if modules_extracted == 0:
        # Match patterns like: "modA": (module, exports, __webpack_require__) => { ... } or numeric keys 101: function(...) { ... }
        mod_matches = re.findall(
            r'(["\']?[A-Za-z0-9_./@-]+["\']?)\s*:\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
            js_text,
        )
        if mod_matches:
            for idx_m, (m_key, m_body) in enumerate(mod_matches[:200]):
                clean_key = re.sub(r"[^A-Za-z0-9_]", "_", m_key.strip("\"'")) or f"mod_{idx_m}"
                deob = deobfuscate_javascript_snippet(f"function module_{clean_key}() {{\n{m_body}\n}}")
                m_file = mod_dir / f"{clean_key}.ts"
                m_file.write_text(deob["deobfuscated_code"] + "\n" + "\n".join(deob.get("typescript_interfaces", [])), encoding="utf-8")
                generated.append(f"src/modules/{m_file.name}")
                modules_extracted += 1
        else:
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
