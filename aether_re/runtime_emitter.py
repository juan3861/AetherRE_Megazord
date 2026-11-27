"""Toolchain Discovery, Native Build & Runtime C Header Emitter (v7.0.0).

Extracted from ``project_reconstructor.py`` to separate C/LLVM twin compilation
and ``AETHER_RT`` runtime shim generation from binary lifting orchestration.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_MSVC_X64_ENV_CACHE: Dict[str, Dict[str, str]] = {}


def _get_msvc_x64_env(vcvars_path: Path) -> Optional[Dict[str, str]]:
    key = str(vcvars_path)
    if key in _MSVC_X64_ENV_CACHE:
        return _MSVC_X64_ENV_CACHE[key]
    bat_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".bat", delete=False, encoding="utf-8") as tf:
            tf.write(f'@echo off\r\ncall "{vcvars_path}" >nul\r\nset\r\n')
            bat_path = Path(tf.name)
        out = subprocess.check_output(
            ["cmd", "/c", str(bat_path)],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        env_map: Dict[str, str] = {}
        for ln in out.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                if k:
                    env_map[k] = v
        if "PATH" in env_map or "Path" in env_map:
            _MSVC_X64_ENV_CACHE[key] = env_map
            return env_map
    except Exception:
        pass
    finally:
        if bat_path is not None:
            bat_path.unlink(missing_ok=True)
    return None


def _find_msvc_x64_toolchain() -> Optional[Tuple[Path, Dict[str, str], str, Optional[str]]]:
    """Locates MSVC vcvars64, cached x64 environment, cl.exe, and link.exe."""
    vswhere = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    vcvars_candidates: List[Path] = []
    if vswhere.is_file():
        try:
            vs_paths = subprocess.check_output(
                [str(vswhere), "-all", "-products", "*", "-property", "installationPath"],
                text=True,
                timeout=10,
            ).splitlines()
            for vp in vs_paths:
                cand = Path(vp.strip()) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
                if cand.is_file():
                    vcvars_candidates.append(cand)
        except Exception:
            pass
    default_vc = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat")
    if default_vc.is_file() and default_vc not in vcvars_candidates:
        vcvars_candidates.append(default_vc)
    if not vcvars_candidates:
        return None
    vc = vcvars_candidates[0]
    cached_env = _get_msvc_x64_env(vc)
    if not cached_env:
        return vc, {}, "", None
    path_str = cached_env.get("Path") or cached_env.get("PATH") or ""
    cl_in_env = shutil.which("cl", path=path_str) or ""
    link_in_env = shutil.which("link", path=path_str)
    if cl_in_env and not link_in_env:
        cand_link = Path(cl_in_env).with_name("link.exe")
        if cand_link.is_file():
            link_in_env = str(cand_link)
    return vc, cached_env, cl_in_env, link_in_env


def _compile_rc_if_present(proj: Path, env: Dict[str, str]) -> Optional[Path]:
    """Compile `resources/reconstructed.rc` into `resources/reconstructed.res` via SDK `rc.exe`."""
    rc_src = proj / "resources" / "reconstructed.rc"
    if not rc_src.is_file():
        return None
    rc_exe = shutil.which("rc", path=env.get("PATH", ""))
    if not rc_exe:
        return None
    res_out = rc_src.with_suffix(".res")
    proc = subprocess.run(
        [rc_exe, "/nologo", "/fo", str(res_out), str(rc_src.name)],
        cwd=str(rc_src.parent),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if proc.returncode == 0 and res_out.is_file() and res_out.stat().st_size > 0:
        return res_out
    return None


def compile_reconstructed_project(
    project_dir: str | Path,
    output_dll_name: str = "reconstructed_twin.dll",
    source_rel: str = "src/reconstructed_project.c",
) -> Dict[str, Any]:
    """Compiles a reconstructed twin C project (single file or `multi_tu` modules) into a native shared library."""
    proj = Path(project_dir).resolve()
    def_file = proj / "src" / "exports.def"
    out_dll = proj / output_dll_name

    if source_rel == "multi_tu":
        c_sources = sorted((proj / "src" / "modules").glob("*.c"))
        if not c_sources:
            return {"compiled": False, "status": "missing_source", "error": f"No modules in {proj / 'src' / 'modules'}"}
    else:
        c_src = proj / source_rel
        if not c_src.is_file():
            return {"compiled": False, "status": "missing_source", "error": f"Not found: {c_src}"}
        c_sources = [c_src]

    vc_info = _find_msvc_x64_toolchain()
    res_embedded = False
    if vc_info is not None:
        vc, cached_env, cl_in_env, _ = vc_info
        src_strs = [str(p) for p in c_sources]
        if cached_env and cl_in_env:
            res_file = _compile_rc_if_present(proj, cached_env)
            cmd_args = [cl_in_env, "/nologo", "/LD", "/O2"]
            if len(c_sources) > 1:
                obj_dir = proj / "build_tu"
                obj_dir.mkdir(parents=True, exist_ok=True)
                cmd_args.append(f"/Fo{obj_dir}{chr(92)}")
            cmd_args.extend(src_strs)
            if res_file is not None:
                cmd_args.append(str(res_file))
                res_embedded = True
            cmd_args.append(f"/Fe:{out_dll}")
            if def_file.is_file():
                cmd_args.extend(["/link", f"/DEF:{def_file}"])
            proc = subprocess.run(
                cmd_args,
                cwd=str(proj),
                env=cached_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
        else:
            def_arg = f'/link /DEF:"{def_file}"' if def_file.is_file() else ""
            quoted_srcs = " ".join(f'"{s}"' for s in src_strs)
            bat_body = (
                "@echo off\n"
                f'call "{vc}" >nul\n'
                f'cd /d "{proj}"\n'
                f'cl /nologo /LD /O2 {quoted_srcs} /Fe:"{out_dll}" {def_arg}\n'
            )
            with tempfile.NamedTemporaryFile("w", suffix=".bat", delete=False, encoding="utf-8") as tf:
                tf.write(bat_body)
                bat_path = Path(tf.name)
            try:
                proc = subprocess.run(
                    ["cmd", "/c", str(bat_path)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=120,
                )
            finally:
                bat_path.unlink(missing_ok=True)
        ok = proc.returncode == 0 and out_dll.is_file() and out_dll.stat().st_size > 0
        return {
            "compiled": ok,
            "status": "compiled" if ok else "compile_failed",
            "compiler": "msvc_cl_x64",
            "translation_units": len(c_sources),
            "resources_embedded": res_embedded,
            "dll_path": str(out_dll) if ok else None,
            "dll_size_bytes": out_dll.stat().st_size if ok else 0,
            "dll_sha256": hashlib.sha256(out_dll.read_bytes()).hexdigest() if ok else None,
            "returncode": proc.returncode,
            "build_output": (proc.stdout + "\n" + proc.stderr).strip()[:1000],
        }

    cc = shutil.which("clang") or shutil.which("gcc")
    if cc:
        cmd = [cc, "-shared", "-O2", *(str(p) for p in c_sources), "-o", str(out_dll)]
        if def_file.is_file():
            cmd.append(str(def_file))
        proc = subprocess.run(cmd, cwd=str(proj), capture_output=True, text=True, timeout=60)
        ok = proc.returncode == 0 and out_dll.is_file() and out_dll.stat().st_size > 0
        return {
            "compiled": ok,
            "status": "compiled" if ok else "compile_failed",
            "compiler": Path(cc).name,
            "translation_units": len(c_sources),
            "dll_path": str(out_dll) if ok else None,
            "dll_size_bytes": out_dll.stat().st_size if ok else 0,
            "dll_sha256": hashlib.sha256(out_dll.read_bytes()).hexdigest() if ok else None,
            "returncode": proc.returncode,
            "build_output": (proc.stdout + "\n" + proc.stderr).strip()[:1000],
        }

    return {"compiled": False, "status": "no_compiler_found", "error": "Neither MSVC cl.exe nor clang/gcc found"}


def compile_reconstructed_executable(
    project_dir: str | Path,
    output_exe_name: str = "reconstructed_twin.exe",
    source_rel: str = "src/reconstructed_project.c",
) -> Dict[str, Any]:
    """Compiles a reconstructed C executable project (.exe) via MSVC cl.exe or clang/gcc."""
    proj = Path(project_dir).resolve()
    c_src = proj / source_rel
    out_exe = proj / output_exe_name
    if not c_src.is_file():
        return {"compiled": False, "status": "missing_source", "error": f"Not found: {c_src}"}

    vc_info = _find_msvc_x64_toolchain()
    if vc_info is not None:
        vc, cached_env, cl_in_env, _ = vc_info
        if cached_env and cl_in_env:
            res_file = _compile_rc_if_present(proj, cached_env)
            cmd_exe = [cl_in_env, "/nologo", "/O2", str(c_src)]
            if res_file is not None:
                cmd_exe.append(str(res_file))
            cmd_exe.append(f"/Fe:{out_exe}")
            proc = subprocess.run(
                cmd_exe,
                cwd=str(proj),
                env=cached_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
            ok = proc.returncode == 0 and out_exe.is_file() and out_exe.stat().st_size > 0
            return {
                "compiled": ok,
                "status": "compiled" if ok else "compile_failed",
                "compiler": "msvc_cl_x64",
                "resources_embedded": res_file is not None,
                "exe_path": str(out_exe) if ok else None,
                "exe_size_bytes": out_exe.stat().st_size if ok else 0,
                "exe_sha256": hashlib.sha256(out_exe.read_bytes()).hexdigest() if ok else None,
                "returncode": proc.returncode,
                "build_output": (proc.stdout + "\n" + proc.stderr).strip()[:1000],
            }

    cc = shutil.which("clang") or shutil.which("gcc")
    if cc:
        proc = subprocess.run([cc, "-O2", str(c_src), "-o", str(out_exe)], cwd=str(proj), capture_output=True, text=True, timeout=60)
        ok = proc.returncode == 0 and out_exe.is_file() and out_exe.stat().st_size > 0
        return {
            "compiled": ok,
            "status": "compiled" if ok else "compile_failed",
            "compiler": Path(cc).name,
            "exe_path": str(out_exe) if ok else None,
            "exe_size_bytes": out_exe.stat().st_size if ok else 0,
            "exe_sha256": hashlib.sha256(out_exe.read_bytes()).hexdigest() if ok else None,
            "returncode": proc.returncode,
            "build_output": (proc.stdout + "\n" + proc.stderr).strip()[:1000],
        }
    return {"compiled": False, "status": "no_compiler_found"}


def compile_llvm_twin_project(
    project_dir: str | Path,
    output_dll_name: str = "reconstructed_twin_llvm.dll",
) -> Dict[str, Any]:
    """Links LLVM O3 COFF object (ir/reconstructed_project.obj) with MSVC runtime shim into a standalone native DLL."""
    proj = Path(project_dir).resolve()
    ir_obj = proj / "ir" / "reconstructed_project.obj"
    shim_c = proj / "src" / "llvm_runtime_shim.c"
    shim_obj = proj / "ir" / "llvm_runtime_shim.obj"
    def_file = proj / "src" / "exports.def"
    out_dll = proj / output_dll_name

    if not ir_obj.is_file():
        return {"compiled": False, "status": "missing_llvm_obj", "error": f"Not found: {ir_obj}"}
    if not shim_c.is_file():
        return {"compiled": False, "status": "missing_shim_source", "error": f"Not found: {shim_c}"}

    vc_info = _find_msvc_x64_toolchain()
    if vc_info is not None:
        vc, cached_env, cl_in_env, link_in_env = vc_info
        if cached_env and cl_in_env and link_in_env:
            cl_cmd = [cl_in_env, "/nologo", "/c", "/O2", f"/Fo:{shim_obj}", str(shim_c)]
            cl_proc = subprocess.run(
                cl_cmd,
                cwd=str(proj),
                env=cached_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
            if cl_proc.returncode != 0 or not shim_obj.is_file():
                return {
                    "compiled": False,
                    "status": "shim_compile_failed",
                    "compiler": "llvm_o3_msvc_link",
                    "returncode": cl_proc.returncode,
                    "build_output": (cl_proc.stdout + "\n" + cl_proc.stderr).strip()[:1000],
                }
            link_cmd = [link_in_env, "/nologo", "/DLL", f"/OUT:{out_dll}"]
            if def_file.is_file():
                link_cmd.append(f"/DEF:{def_file}")
            link_cmd.extend([str(ir_obj), str(shim_obj)])
            proc = subprocess.run(
                link_cmd,
                cwd=str(proj),
                env=cached_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
        else:
            def_arg = f'/DEF:"{def_file}"' if def_file.is_file() else ""
            bat_body = (
                "@echo off\n"
                f'call "{vc}" >nul\n'
                f'cd /d "{proj}"\n'
                f'cl /nologo /c /O2 /Fo:"{shim_obj}" "{shim_c}"\n'
                f'if errorlevel 1 exit /b %errorlevel%\n'
                f'link /nologo /DLL /OUT:"{out_dll}" {def_arg} "{ir_obj}" "{shim_obj}"\n'
            )
            with tempfile.NamedTemporaryFile("w", suffix=".bat", delete=False, encoding="utf-8") as tf:
                tf.write(bat_body)
                bat_path = Path(tf.name)
            try:
                proc = subprocess.run(
                    ["cmd", "/c", str(bat_path)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=120,
                )
            finally:
                bat_path.unlink(missing_ok=True)
        ok = proc.returncode == 0 and out_dll.is_file() and out_dll.stat().st_size > 0
        return {
            "compiled": ok,
            "status": "compiled" if ok else "link_failed",
            "compiler": "llvm_o3_msvc_link",
            "dll_path": str(out_dll) if ok else None,
            "dll_size_bytes": out_dll.stat().st_size if ok else 0,
            "dll_sha256": hashlib.sha256(out_dll.read_bytes()).hexdigest() if ok else None,
            "returncode": proc.returncode,
            "build_output": (proc.stdout + "\n" + proc.stderr).strip()[:1000],
        }

    cc = shutil.which("clang")
    if cc:
        cmd = [cc, "-shared", "-O2", str(ir_obj), str(shim_c), "-o", str(out_dll)]
        if def_file.is_file():
            cmd.append(str(def_file))
        proc = subprocess.run(cmd, cwd=str(proj), capture_output=True, text=True, timeout=60)
        ok = proc.returncode == 0 and out_dll.is_file() and out_dll.stat().st_size > 0
        return {
            "compiled": ok,
            "status": "compiled" if ok else "link_failed",
            "compiler": "llvm_o3_clang_link",
            "dll_path": str(out_dll) if ok else None,
            "dll_size_bytes": out_dll.stat().st_size if ok else 0,
            "dll_sha256": hashlib.sha256(out_dll.read_bytes()).hexdigest() if ok else None,
            "returncode": proc.returncode,
            "build_output": (proc.stdout + "\n" + proc.stderr).strip()[:1000],
        }

    return {"compiled": False, "status": "no_linker_found", "error": "Neither MSVC link.exe nor clang found"}


def _base_runtime_header_lines() -> List[str]:
    """Shared AETHER_RT runtime header preamble reused by PE x86-64, PE ARM64, and ELF64 targets."""
    return [
        "/* Auto-Reconstructed Public Header by AetherRE Megazord (GEAR-23) */",
        "#pragma once",
        "#ifndef _CRT_SECURE_NO_WARNINGS",
        "#define _CRT_SECURE_NO_WARNINGS",
        "#endif",
        "#include <ctype.h>",
        "#include <math.h>",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        "#ifdef __cplusplus",
        'extern "C" {',
        "#endif",
        "#ifdef AETHER_RT_LINK",
        "#define AETHER_RT",
        "#else",
        "#define AETHER_RT static inline",
        "#endif",
        "",
        "AETHER_RT int64_t aether_malloc(int64_t size) {",
        "    return (int64_t)(uintptr_t)malloc((size_t)(size > 0 ? size : 1));",
        "}",
        "AETHER_RT int64_t aether_free(int64_t ptr) {",
        "    free((void*)(uintptr_t)ptr);",
        "    return 0LL;",
        "}",
        "AETHER_RT int64_t aether_realloc(int64_t ptr, int64_t size) {",
        "    return (int64_t)(uintptr_t)realloc((void*)(uintptr_t)ptr, (size_t)(size > 0 ? size : 1));",
        "}",
        "AETHER_RT int64_t aether_strlen(int64_t s) {",
        "    if (!s) return 0LL;",
        "    return (int64_t)strlen((const char*)(uintptr_t)s);",
        "}",
        "AETHER_RT int64_t aether_strcmp(int64_t a, int64_t b) {",
        '    const char* sa = a ? (const char*)(uintptr_t)a : "";',
        '    const char* sb = b ? (const char*)(uintptr_t)b : "";',
        "    return (int64_t)strcmp(sa, sb);",
        "}",
        "AETHER_RT int64_t aether_strncmp(int64_t a, int64_t b, int64_t n) {",
        "    if (!a || !b || n <= 0) return 0LL;",
        "    return (int64_t)strncmp((const char*)(uintptr_t)a, (const char*)(uintptr_t)b, (size_t)n);",
        "}",
        "AETHER_RT int64_t aether_sprintf(int64_t buf, int64_t fmt, int64_t a1, int64_t a2, int64_t a3) {",
        "    if (!buf || !fmt) return -1LL;",
        "    const char* fs = (const char*)(uintptr_t)fmt;",
        "    if (strchr(fs, 'g') || strchr(fs, 'f') || strchr(fs, 'e')) {",
        "        double d_val = 0.0;",
        "        memcpy(&d_val, &a1, 8);",
        "        return (int64_t)sprintf((char*)(uintptr_t)buf, fs, d_val);",
        "    }",
        "    return (int64_t)sprintf((char*)(uintptr_t)buf, fs, a1, a2, a3);",
        "}",
        "AETHER_RT int64_t aether_sscanf(int64_t buf, int64_t fmt, int64_t a1, int64_t a2) {",
        "    if (!buf || !fmt) return -1LL;",
        "    (void)a2;",
        "    return (int64_t)sscanf((const char*)(uintptr_t)buf, (const char*)(uintptr_t)fmt, (void*)(uintptr_t)a1);",
        "}",
        "AETHER_RT double aether_strtod(int64_t s, int64_t endptr) {",
        "    if (!s) { if (endptr) *(char**)(uintptr_t)endptr = NULL; return 0.0; }",
        "    return strtod((const char*)(uintptr_t)s, (char**)(uintptr_t)endptr);",
        "}",
        "AETHER_RT int64_t aether_printf(int64_t fmt, int64_t a1, int64_t a2, int64_t a3) {",
        "    if (!fmt) return -1LL;",
        "    const char* fs = (const char*)(uintptr_t)fmt;",
        "    if (strchr(fs, 'g') || strchr(fs, 'f') || strchr(fs, 'e')) {",
        "        double d_val = 0.0;",
        "        memcpy(&d_val, &a1, 8);",
        "        return (int64_t)printf(fs, d_val);",
        "    }",
        "    return (int64_t)printf(fs, a1, a2, a3);",
        "}",
        "AETHER_RT int64_t aether_pcmpeqb64(int64_t a, int64_t b) {",
        "    uint64_t out = 0, ua = (uint64_t)a, ub = (uint64_t)b;",
        "    for (int i = 0; i < 8; ++i) {",
        "        if (((ua >> (i * 8)) & 0xffULL) == ((ub >> (i * 8)) & 0xffULL)) out |= (0xffULL << (i * 8));",
        "    }",
        "    return (int64_t)out;",
        "}",
        "AETHER_RT int64_t aether_pmaxud64(int64_t a, int64_t b) {",
        "    uint32_t al = (uint32_t)a, bl = (uint32_t)b, ah = (uint32_t)((uint64_t)a >> 32), bh = (uint32_t)((uint64_t)b >> 32);",
        "    return (int64_t)((uint64_t)(al > bl ? al : bl) | ((uint64_t)(ah > bh ? ah : bh) << 32));",
        "}",
        "AETHER_RT int64_t aether_pcmpeqd64(int64_t a, int64_t b) {",
        "    uint32_t al = (uint32_t)a, bl = (uint32_t)b, ah = (uint32_t)((uint64_t)a >> 32), bh = (uint32_t)((uint64_t)b >> 32);",
        "    return (int64_t)((al == bl ? 0xffffffffULL : 0ULL) | ((ah == bh ? 0xffffffffULL : 0ULL) << 32));",
        "}",
        "AETHER_RT int64_t aether_psubd64(int64_t a, int64_t b) {",
        "    uint32_t al = (uint32_t)a - (uint32_t)b, ah = (uint32_t)((uint64_t)a >> 32) - (uint32_t)((uint64_t)b >> 32);",
        "    return (int64_t)((uint64_t)al | ((uint64_t)ah << 32));",
        "}",
        "static int64_t _aether_xmm_hi = 0;",
        "static inline int64_t aether_pshufd(int64_t lo, int64_t hi, int64_t imm8) {",
        "    uint32_t L[4] = { (uint32_t)lo, (uint32_t)((uint64_t)lo >> 32), (uint32_t)hi, (uint32_t)((uint64_t)hi >> 32) };",
        "    _aether_xmm_hi = (int64_t)((uint64_t)L[(imm8 >> 4) & 3] | ((uint64_t)L[(imm8 >> 6) & 3] << 32));",
        "    return (int64_t)((uint64_t)L[imm8 & 3] | ((uint64_t)L[(imm8 >> 2) & 3] << 32));",
        "}",
        "AETHER_RT int64_t aether_tolower(int64_t c) {",
        "    return (int64_t)tolower((int)(unsigned char)c);",
        "}",
        "AETHER_RT int64_t aether_isalpha(int64_t c) { return (int64_t)isalpha((int)(unsigned char)c); }",
        "AETHER_RT int64_t aether_isdigit(int64_t c) { return (int64_t)isdigit((int)(unsigned char)c); }",
        "AETHER_RT int64_t aether_isspace(int64_t c) { return (int64_t)isspace((int)(unsigned char)c); }",
        "AETHER_RT int64_t aether_isxdigit(int64_t c) { return (int64_t)isxdigit((int)(unsigned char)c); }",
        "AETHER_RT int64_t aether_memcpy(int64_t dst, int64_t src, int64_t size) {",
        "    if (dst && src && size > 0) memcpy((void*)(uintptr_t)dst, (const void*)(uintptr_t)src, (size_t)size);",
        "    return dst;",
        "}",
        "AETHER_RT int64_t aether_memset(int64_t dst, int64_t val, int64_t size) {",
        "    if (dst && size > 0) memset((void*)(uintptr_t)dst, (int)(unsigned char)val, (size_t)size);",
        "    return dst;",
        "}",
        "AETHER_RT double aether_pow(double a, double b) { return pow(a, b); }",
        "AETHER_RT double aether_fmod(double a, double b) { return fmod(a, b); }",
        "#ifdef AETHER_MULTI_TU_DECL",
        "extern int64_t _aether_div_rem;",
        "extern int64_t _aether_imul_hi;",
        "#elif defined(AETHER_MULTI_TU_IMPL)",
        "int64_t _aether_div_rem = 0;",
        "int64_t _aether_imul_hi = 0;",
        "#else",
        "static int64_t _aether_div_rem = 0;",
        "static int64_t _aether_imul_hi = 0;",
        "#endif",
        "static inline int64_t aether_udiv64(int64_t hi, int64_t lo, int64_t d) {",
        "    uint64_t ud = (uint64_t)d;",
        "    if (!ud) { _aether_div_rem = 0; return 0; }",
        "    if (hi == 0) { uint64_t ul = (uint64_t)lo; _aether_div_rem = (int64_t)(ul % ud); return (int64_t)(ul / ud); }",
        "    uint64_t q = 0, r = (uint64_t)hi, u_lo = (uint64_t)lo;",
        "    for (int i = 63; i >= 0; --i) {",
        "        uint64_t c = r >> 63;",
        "        r = (r << 1) | ((u_lo >> i) & 1ULL);",
        "        if (c || r >= ud) { r -= ud; q |= (1ULL << i); }",
        "    }",
        "    _aether_div_rem = (int64_t)r;",
        "    return (int64_t)q;",
        "}",
        "static inline int64_t aether_udiv32(int64_t hi, int64_t lo, int64_t d) {",
        "    uint64_t ud = (uint64_t)(uint32_t)d;",
        "    if (!ud) { _aether_div_rem = 0; return 0; }",
        "    uint64_t un = ((uint64_t)(uint32_t)hi << 32) | (uint64_t)(uint32_t)lo;",
        "    _aether_div_rem = (int64_t)(uint32_t)(un % ud);",
        "    return (int64_t)(uint32_t)(un / ud);",
        "}",
        "static inline int64_t aether_imul32(int64_t a, int64_t b) {",
        "    int64_t prod = (int64_t)(int32_t)a * (int64_t)(int32_t)b;",
        "    _aether_imul_hi = (int64_t)(uint32_t)((uint64_t)prod >> 32);",
        "    return (int64_t)(uint32_t)prod;",
        "}",
        "static inline int64_t aether_imul64(int64_t a, int64_t b) {",
        "    uint64_t ua = (uint64_t)(a < 0 ? -a : a), ub = (uint64_t)(b < 0 ? -b : b);",
        "    uint64_t a_lo = ua & 0xffffffffULL, a_hi = ua >> 32;",
        "    uint64_t b_lo = ub & 0xffffffffULL, b_hi = ub >> 32;",
        "    uint64_t p0 = a_lo * b_lo, p1 = a_lo * b_hi, p2 = a_hi * b_lo, p3 = a_hi * b_hi;",
        "    uint64_t mid = (p0 >> 32) + (p1 & 0xffffffffULL) + (p2 & 0xffffffffULL);",
        "    uint64_t lo = (p0 & 0xffffffffULL) | (mid << 32);",
        "    uint64_t hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);",
        "    if ((a < 0) ^ (b < 0)) { lo = ~lo + 1ULL; hi = ~hi + (lo == 0 ? 1ULL : 0ULL); }",
        "    _aether_imul_hi = (int64_t)hi;",
        "    return (int64_t)lo;",
        "}",
        "static inline int64_t aether_umul32(int64_t a, int64_t b) {",
        "    uint64_t prod = (uint64_t)(uint32_t)a * (uint64_t)(uint32_t)b;",
        "    _aether_imul_hi = (int64_t)(uint32_t)(prod >> 32);",
        "    return (int64_t)(uint32_t)prod;",
        "}",
        "static inline int64_t aether_umul64(int64_t a, int64_t b) {",
        "    uint64_t ua = (uint64_t)a, ub = (uint64_t)b;",
        "    uint64_t a_lo = ua & 0xffffffffULL, a_hi = ua >> 32;",
        "    uint64_t b_lo = ub & 0xffffffffULL, b_hi = ub >> 32;",
        "    uint64_t p0 = a_lo * b_lo, p1 = a_lo * b_hi, p2 = a_hi * b_lo, p3 = a_hi * b_hi;",
        "    uint64_t mid = (p0 >> 32) + (p1 & 0xffffffffULL) + (p2 & 0xffffffffULL);",
        "    uint64_t lo = (p0 & 0xffffffffULL) | (mid << 32);",
        "    uint64_t hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);",
        "    _aether_imul_hi = (int64_t)hi;",
        "    return (int64_t)lo;",
        "}",
        "static inline int64_t aether_tzcnt32(int64_t v) {",
        "    uint32_t uv = (uint32_t)v;",
        "    if (!uv) return 32;",
        "    int64_t c = 0; while ((uv & 1U) == 0) { uv >>= 1; ++c; }",
        "    return c;",
        "}",
        "static inline int64_t aether_tzcnt64(int64_t v) {",
        "    uint64_t uv = (uint64_t)v;",
        "    if (!uv) return 64;",
        "    int64_t c = 0; while ((uv & 1ULL) == 0) { uv >>= 1; ++c; }",
        "    return c;",
        "}",
        "AETHER_RT int64_t aether_calloc(int64_t n, int64_t sz) {",
        "    return (int64_t)(uintptr_t)calloc((size_t)(n > 0 ? n : 1), (size_t)(sz > 0 ? sz : 1));",
        "}",
        "AETHER_RT int64_t aether_rep_stos(int64_t dst, int64_t val, int64_t count, int64_t width) {",
        "    if (!dst || count <= 0) return dst;",
        "    uint64_t cnt = (uint64_t)count;",
        "    if (width == 1) { memset((void*)(uintptr_t)dst, (int)(unsigned char)val, (size_t)cnt); return dst + (int64_t)cnt; }",
        "    if (width == 2) { uint16_t *p = (uint16_t*)(uintptr_t)dst; for (uint64_t i = 0; i < cnt; ++i) p[i] = (uint16_t)val; return dst + (int64_t)(cnt * 2); }",
        "    if (width == 4) { uint32_t *p = (uint32_t*)(uintptr_t)dst; for (uint64_t i = 0; i < cnt; ++i) p[i] = (uint32_t)val; return dst + (int64_t)(cnt * 4); }",
        "    uint64_t *p = (uint64_t*)(uintptr_t)dst; for (uint64_t i = 0; i < cnt; ++i) p[i] = (uint64_t)val; return dst + (int64_t)(cnt * 8);",
        "}",
        "AETHER_RT int64_t aether_strcpy(int64_t dst, int64_t src) {",
        "    if (dst && src) {",
        "        size_t n = strlen((const char*)(uintptr_t)src) + 1;",
        "        memcpy((void*)(uintptr_t)dst, (const void*)(uintptr_t)src, n);",
        "    }",
        "    return dst;",
        "}",
        "AETHER_RT int64_t aether_strrchr(int64_t s, int64_t ch) {",
        "    return s ? (int64_t)(uintptr_t)strrchr((const char*)(uintptr_t)s, (int)(unsigned char)ch) : 0;",
        "}",
        "static inline int64_t aether_u32(uint64_t v) {",
        "    return (int64_t)(uint32_t)v;",
        "}",
        "static inline int64_t aether_i32(int64_t v) {",
        "    return (int64_t)(int32_t)v;",
        "}",
        "static inline int64_t aether_i16(int64_t v) {",
        "    return (int64_t)(int16_t)(uint16_t)v;",
        "}",
        "static inline int64_t aether_i8(int64_t v) {",
        "    return (int64_t)(int8_t)(uint8_t)v;",
        "}",
        "static inline int64_t aether_bt_cf(int64_t val, int64_t bit, int64_t mask) {",
        "    return ((((uint64_t)val) >> ((uint64_t)bit & (uint64_t)mask)) & 1ULL) ? 0LL : 1LL;",
        "}",
        "static inline int64_t aether_bit_mask(int64_t bit, int64_t mask) {",
        "    return (int64_t)(1ULL << ((uint64_t)bit & (uint64_t)mask));",
        "}",
        "#ifdef _MSC_VER",
        "#define AETHER_TLS __declspec(thread)",
        "#define AETHER_ALIGN16 __declspec(align(16))",
        "#else",
        "#define AETHER_TLS _Thread_local",
        "#define AETHER_ALIGN16 __attribute__((aligned(16)))",
        "#endif",
        "#ifdef AETHER_MULTI_TU_DECL",
        "extern AETHER_TLS AETHER_ALIGN16 uint8_t aether_tls_stack[131072];",
        "extern AETHER_TLS int64_t _aether_sp;",
        "#elif defined(AETHER_MULTI_TU_IMPL)",
        "AETHER_TLS AETHER_ALIGN16 uint8_t aether_tls_stack[131072];",
        "AETHER_TLS int64_t _aether_sp = 0;",
        "#else",
        "static AETHER_TLS AETHER_ALIGN16 uint8_t aether_tls_stack[131072];",
        "static AETHER_TLS int64_t _aether_sp = 0;",
        "#endif",
        "AETHER_RT int64_t aether_get_sp(void) {",
        "    return _aether_sp;",
        "}",
        "AETHER_RT int64_t aether_set_sp(int64_t sp) {",
        "    _aether_sp = sp;",
        "    return sp;",
        "}",
        "AETHER_RT int64_t aether_stack_base(void) {",
        "    return (_aether_sp ? _aether_sp : (int64_t)(uintptr_t)(aether_tls_stack + 114688)) - 8;",
        "}",
        "static inline int64_t aether_set_byte(int64_t reg, int cond) {",
        "    return (reg & ~0xffLL) | (cond ? 1LL : 0LL);",
        "}",
        "AETHER_RT uint64_t aether_mem_read(int64_t addr, size_t width) {",
        "    if (addr == 0) return 0ULL;",
        "    const uint8_t* p = (const uint8_t*)(uintptr_t)addr;",
        "    if (width == 1) return *(const uint8_t*)p;",
        "    if (width == 2) return *(const uint16_t*)p;",
        "    if (width == 4) return *(const uint32_t*)p;",
        "    return *(const uint64_t*)p;",
        "}",
        "AETHER_RT void aether_mem_write(int64_t addr, size_t width, uint64_t val) {",
        "    if (addr == 0) return;",
        "    uint8_t* p = (uint8_t*)(uintptr_t)addr;",
        "    if (width == 1) *(uint8_t*)p = (uint8_t)val;",
        "    else if (width == 2) *(uint16_t*)p = (uint16_t)val;",
        "    else if (width == 4) *(uint32_t*)p = (uint32_t)val;",
        "    else *(uint64_t*)p = val;",
        "}",
        "static inline int64_t aether_f64_to_bits(double d) {",
        "    int64_t b = 0;",
        "    memcpy(&b, &d, 8);",
        "    return b;",
        "}",
        "static inline double aether_bits_to_f64(int64_t b) {",
        "    double d = 0.0;",
        "    memcpy(&d, &b, 8);",
        "    return d;",
        "}",
        "static inline int64_t aether_f64_comisd(int64_t a_bits, int64_t b_bits) {",
        "    double a = aether_bits_to_f64(a_bits);",
        "    double b = aether_bits_to_f64(b_bits);",
        "    if (isnan(a) || isnan(b)) return -1LL;",
        "    if (a == b) return 1LL;",
        "    if (a > b) return 2LL;",
        "    return 0LL;",
        "}",
        "static inline int64_t aether_f64_to_i32(int64_t b) {",
        "    return (int64_t)(uint32_t)(int32_t)aether_bits_to_f64(b);",
        "}",
        "static inline int64_t aether_i32_to_f64(int64_t i) {",
        "    return aether_f64_to_bits((double)(int32_t)i);",
        "}",
        "static inline int64_t aether_f32_to_f64(int64_t u32_bits) {",
        "    float f = 0.0f;",
        "    uint32_t u = (uint32_t)u32_bits;",
        "    memcpy(&f, &u, 4);",
        "    return aether_f64_to_bits((double)f);",
        "}",
        "static inline int64_t aether_f64_max(int64_t a, int64_t b) { return aether_bits_to_f64(a) > aether_bits_to_f64(b) ? a : b; }",
        "static inline int64_t aether_f64_min(int64_t a, int64_t b) { return aether_bits_to_f64(a) < aether_bits_to_f64(b) ? a : b; }",
        "static inline int64_t aether_f64_add(int64_t a, int64_t b) { return aether_f64_to_bits(aether_bits_to_f64(a) + aether_bits_to_f64(b)); }",
        "static inline int64_t aether_f64_sub(int64_t a, int64_t b) { return aether_f64_to_bits(aether_bits_to_f64(a) - aether_bits_to_f64(b)); }",
        "static inline int64_t aether_f64_mul(int64_t a, int64_t b) { return aether_f64_to_bits(aether_bits_to_f64(a) * aether_bits_to_f64(b)); }",
        "static inline int64_t aether_f64_div(int64_t a, int64_t b) { return aether_f64_to_bits(aether_bits_to_f64(a) / aether_bits_to_f64(b)); }",
        "AETHER_RT int64_t aether_f64_fma(int64_t a, int64_t b, int64_t c) { return aether_f64_to_bits(aether_bits_to_f64(a) * aether_bits_to_f64(b) + aether_bits_to_f64(c)); }",
        "AETHER_RT int64_t aether_vpaddd64(int64_t a, int64_t b) {",
        "    uint32_t al = (uint32_t)a + (uint32_t)b;",
        "    uint32_t ah = (uint32_t)((uint64_t)a >> 32) + (uint32_t)((uint64_t)b >> 32);",
        "    return (int64_t)((uint64_t)al | ((uint64_t)ah << 32));",
        "}",
        "AETHER_RT int64_t aether_vpsubd64(int64_t a, int64_t b) { return aether_psubd64(a, b); }",
        "#ifdef _WIN32",
        "__declspec(dllimport) void* __stdcall LoadLibraryA(const char* lpLibFileName);",
        "__declspec(dllimport) void* __stdcall GetProcAddress(void* hModule, const char* lpProcName);",
        "#else",
        "#include <dlfcn.h>",
        "#endif",
        "typedef int64_t (*_aether_iat8_fn)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);",
        "AETHER_RT int64_t aether_iat_call(const char* dll_name, const char* sym_name, int64_t a1, int64_t a2, int64_t a3, int64_t a4, int64_t a5, int64_t a6, int64_t a7, int64_t a8) {",
        "#ifdef _WIN32",
        "    void* mod = LoadLibraryA(dll_name);",
        "    void* fn = mod ? GetProcAddress(mod, sym_name) : NULL;",
        "#else",
        "    void* mod = dlopen(dll_name, 1);",
        "    void* fn = mod ? dlsym(mod, sym_name) : NULL;",
        "#endif",
        "    if (!fn) return 0;",
        "    return ((_aether_iat8_fn)fn)(a1, a2, a3, a4, a5, a6, a7, a8);",
        "}",
        "",
    ]


def emit_partitioned_c_modules(
    out_root: Path,
    records_list: Sequence[Dict[str, Any]],
    *,
    extra_stubs: Sequence[str] = (),
    is_executable_entry: bool = False,
    arch_label: str = "x86_64",
) -> List[str]:
    """Partitions reconstructed C functions into modular `src/modules/*.c` translation units + `CMakeLists.multi_tu.txt`."""
    mod_dir = out_root / "src" / "modules"
    mod_dir.mkdir(parents=True, exist_ok=True)

    buckets: Dict[str, List[str]] = {}
    for idx, rec in enumerate(records_list):
        c_code = str(rec.get("c_code", "")).strip()
        if not c_code:
            continue
        sym = str(rec.get("c_ident") or rec.get("symbol") or rec.get("c_symbol") or rec.get("name") or f"fn_{idx}")
        if sym.startswith("sub_"):
            group = "internal"
        elif "_" in sym:
            pref = re.sub(r"[^a-z0-9]", "", sym.split("_", 1)[0].lower())
            group = pref or "core"
        else:
            group = f"unit_{idx % 4}" if len(records_list) >= 2 else "core"
        buckets.setdefault(group, []).append(c_code)

    # Collapse small/excess prefix buckets cleanly while keeping >=2 TUs when multiple functions exist
    if len(buckets) > 12:
        sorted_groups = sorted(buckets.items(), key=lambda kv: -len(kv[1]))
        kept: Dict[str, List[str]] = {k: v for k, v in sorted_groups[:11]}
        overflow: List[str] = []
        for _k, v in sorted_groups[11:]:
            overflow.extend(v)
        kept["misc"] = overflow
        buckets = kept
    elif len(buckets) == 1 and len(records_list) >= 2:
        only_items = next(iter(buckets.values()))
        mid = len(only_items) // 2
        buckets = {"part_0": only_items[:mid], "part_1": only_items[mid:]}

    generated: List[str] = []
    tu_rels: List[str] = []
    for g_name, bodies in sorted(buckets.items()):
        rel = f"src/modules/mod_{g_name}.c"
        txt = "\n".join([
            f"/* Auto-Partitioned Translation Unit `{g_name}` ({arch_label}) by AetherRE v8.4 */",
            "#define AETHER_MULTI_TU_DECL 1",
            '#include "../../include/reconstructed_api.h"',
            "",
            *bodies,
            "",
        ])
        (out_root / rel).write_text(txt, encoding="utf-8")
        generated.append(rel)
        tu_rels.append(rel)

    if extra_stubs:
        rel_s = "src/modules/mod_stubs.c"
        txt_s = "\n".join([
            f"/* External/Unresolved Stubs Translation Unit ({arch_label}) by AetherRE v8.4 */",
            "#define AETHER_MULTI_TU_DECL 1",
            '#include "../../include/reconstructed_api.h"',
            "",
            *extra_stubs,
            "",
        ])
        (out_root / rel_s).write_text(txt_s, encoding="utf-8")
        generated.append(rel_s)
        tu_rels.append(rel_s)

    if is_executable_entry:
        rel_e = "src/modules/mod_entry.c"
        txt_e = "\n".join([
            f"/* Entrypoint Wrapper Translation Unit ({arch_label}) by AetherRE v8.4 */",
            "#define AETHER_MULTI_TU_DECL 1",
            '#include "../../include/reconstructed_api.h"',
            "",
            "int main(int argc, char** argv) {",
            "    (void)argc; (void)argv;",
            "    return (int)main_entry(0, 0, 0, 0);",
            "}",
            "",
        ])
        (out_root / rel_e).write_text(txt_e, encoding="utf-8")
        generated.append(rel_e)
        tu_rels.append(rel_e)

    rel_rt = "src/modules/mod_runtime_shared.c"
    txt_rt = "\n".join([
        f"/* Shared Multi-TU .data/.rdata/vtable/TLS Runtime State ({arch_label}) by AetherRE v8.4 */",
        "#define AETHER_RT_LINK 1",
        "#define AETHER_MULTI_TU_IMPL 1",
        '#include "../../include/reconstructed_api.h"',
        "",
    ])
    (out_root / rel_rt).write_text(txt_rt, encoding="utf-8")
    generated.append(rel_rt)
    tu_rels.append(rel_rt)

    target_kind = "add_executable(reconstructed_twin " + " ".join(tu_rels) + ")" if is_executable_entry else (
        "add_library(reconstructed_twin SHARED " + " ".join(tu_rels) + " src/exports.def)"
    )
    cmake_multi = "\n".join([
        "cmake_minimum_required(VERSION 3.16)",
        "project(reconstructed_twin_multi_tu LANGUAGES C)",
        target_kind,
        "target_include_directories(reconstructed_twin PUBLIC include)",
        "",
    ])
    (out_root / "CMakeLists.multi_tu.txt").write_text(cmake_multi, encoding="utf-8")
    generated.append("CMakeLists.multi_tu.txt")
    return generated
