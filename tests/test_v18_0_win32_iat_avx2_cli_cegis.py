"""Pilar 13 (v18.0): Win32/POSIX Dynamic IAT Bridge, >4 Stack Args, AVX/AVX2 & Process/Buffer CEGIS."""

from __future__ import annotations

from pathlib import Path
import subprocess

import keystone
import pytest

from aether_re.differential_certifier import (
    certify_buffer_function_parity,
    certify_cli_executable_parity,
    locate_divergence_rva,
)
from aether_re.project_reconstructor import _lift_x64_function_full, reconstruct_project
from aether_re.runtime_emitter import (
    _find_msvc_x64_toolchain,
    compile_reconstructed_project,
)


def _asm64(asm: str) -> bytes:
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    enc, _ = ks.asm(asm)
    return bytes(enc)


def test_lifter_avx2_stack_args_and_dynamic_iat_bridge() -> None:
    # 1. AVX2 vmovdqu + vpaddd + vpxor + vfmadd213sd
    avx_bytes = _asm64(
        "vmovdqu ymm0, ymmword ptr [rcx]; "
        "vmovdqu ymm1, ymmword ptr [rdx]; "
        "vpaddd ymm0, ymm0, ymm1; "
        "vpxor ymm0, ymm0, ymm1; "
        "vfmadd213sd xmm0, xmm1, xmm2; "
        "ret"
    )
    c_avx, _, lifted_avx, _, _, _, _ = _lift_x64_function_full("avx_fn", avx_bytes, 0x1000)
    assert lifted_avx is True
    assert "aether_vpaddd64" in c_avx
    assert "aether_f64_fma" in c_avx
    assert "ymm0_y2" in c_avx or "xmm0_y2" in c_avx

    # 2. >4 stack args ([rsp + 0x28..0x40])
    stk_bytes = _asm64(
        "mov rax, rcx; "
        "add rax, rdx; "
        "add rax, r8; "
        "add rax, r9; "
        "add rax, qword ptr [rsp + 0x28]; "
        "add rax, qword ptr [rsp + 0x30]; "
        "add rax, qword ptr [rsp + 0x38]; "
        "add rax, qword ptr [rsp + 0x40]; "
        "ret"
    )
    c_stk, _, lifted_stk, _, _, _, _ = _lift_x64_function_full("sum8", stk_bytes, 0x2000)
    assert lifted_stk is True
    assert "int64_t stk0, int64_t stk1, int64_t stk2, int64_t stk3" in c_stk
    assert "aether_mem_write(rsp + 0x28, 8, stk0)" in c_stk

    # 3. Dynamic Host IAT Bridge (call qword ptr [rip + disp])
    # sub rsp, 0x28 (4B) -> call at RVA 0x3004 (len 6) -> target RVA 0x400a
    iat_bytes = _asm64("sub rsp, 0x28; call qword ptr [rip + 0x1000]; add rsp, 0x28; ret")
    c_iat, _, _, _, _, _, _ = _lift_x64_function_full(
        "iat_fn",
        iat_bytes,
        0x3000,
        iat_rva_map={0x400A: ("kernel32.dll", "GetTickCount64")},
    )
    assert 'aether_iat_call("kernel32.dll", "GetTickCount64"' in c_iat


def test_real_msvc_dll_buffer_parity_and_unicorn_divergence_trace(tmp_path: Path) -> None:
    vc = _find_msvc_x64_toolchain()
    if vc is None:
        pytest.skip("MSVC x64 toolchain required")
    _, env, cl_exe, _ = vc

    src = tmp_path / "buf_orig.c"
    dll = tmp_path / "buf_orig.dll"
    src.write_text(
        r"""
#include <stdint.h>
#include <stddef.h>

__declspec(dllexport) int64_t buf_xor_hash(uint8_t* buf, uint64_t len) {
    int64_t acc = 0x1357;
    for (uint64_t i = 0; i < len; ++i) {
        buf[i] ^= (uint8_t)((i * 7 + 0x5A) & 0xFF);
        acc = (acc * 31) ^ (int64_t)buf[i];
    }
    return acc;
}
""",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [cl_exe, "/nologo", "/O2", "/LD", str(src), f"/Fe:{dll}"],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    twin_dir = tmp_path / "twin_proj"
    reconstruct_project(dll, twin_dir)
    comp = compile_reconstructed_project(twin_dir)
    assert comp["compiled"] is True, comp

    payloads = [b"", b"A", b"AetherRE_v18_Field_Reality!", bytes(range(64))]
    buf_cert = certify_buffer_function_parity(dll, twin_dir, "buf_xor_hash", payloads)
    assert buf_cert["certified_100pct"] is True, buf_cert
    assert buf_cert["differential_parity_pct"] == 100.0

    # Unicorn trace divergence locator on exported RVA
    import pefile

    pe = pefile.PE(str(dll), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    rva = pe.DIRECTORY_ENTRY_EXPORT.symbols[0].address
    tr = locate_divergence_rva(dll, rva, regs_init={"rcx": 0, "rdx": 0}, max_steps=16)
    assert tr["steps"] >= 1


def test_real_win32_cli_executable_parity_certifier(tmp_path: Path) -> None:
    vc = _find_msvc_x64_toolchain()
    if vc is None:
        pytest.skip("MSVC x64 toolchain required")
    _, env, cl_exe, _ = vc

    cli_c = tmp_path / "cli_app.c"
    orig_exe = tmp_path / "orig_cli.exe"
    twin_exe = tmp_path / "twin_cli.exe"
    code = r"""
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    char envbuf[128] = {0};
    DWORD n = GetEnvironmentVariableA("COMPUTERNAME", envbuf, sizeof(envbuf));
    const char* arg1 = (argc > 1) ? argv[1] : "default";
    printf("AETHER_CLI:%s:%lu\n", arg1, (unsigned long)(n > 0 ? 1 : 0));
    HANDLE h = CreateFileA("out.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(h, arg1, (DWORD)strlen(arg1), &wr, NULL);
        CloseHandle(h);
    }
    return (argc > 1 && strcmp(argv[1], "fail") == 0) ? 2 : 0;
}
"""
    cli_c.write_text(code, encoding="utf-8")
    p1 = subprocess.run([cl_exe, "/nologo", "/O2", str(cli_c), f"/Fe:{orig_exe}"], cwd=tmp_path, env=env, capture_output=True, text=True)
    p2 = subprocess.run([cl_exe, "/nologo", "/O2", str(cli_c), f"/Fe:{twin_exe}"], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert p1.returncode == 0 and p2.returncode == 0

    cert = certify_cli_executable_parity(
        orig_exe,
        twin_exe,
        [
            {"argv": ["hello_win32"], "output_files": ["out.txt"]},
            {"argv": ["fail"], "output_files": ["out.txt"]},
        ],
    )
    assert cert["certified_100pct"] is True
    assert cert["differential_parity_pct"] == 100.0
