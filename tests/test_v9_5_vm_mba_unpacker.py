"""Pilar 2 (v9.5) Empirical Tests: MBA Z3 Synthesis, CFF Dispatcher + MBA, VM Trace-to-IR & PEB/ELF Unpacking."""
from __future__ import annotations

import struct
from pathlib import Path

from aether_re.cff_devirtualizer import unflatten_cff_function
from aether_re.dynamic_unpacker import unpack_elf_in_sandbox, unpack_pe_in_sandbox
from aether_re.mba_synthesizer import simplify_mba_expr, solve_opaque_predicate_z3
from aether_re.project_reconstructor import _execute_lifted_c_ast
from aether_re.vm_devirtualizer import detect_vm_dispatchers, devirtualize_vm_via_unicorn_trace


def test_v95_mba_z3_synthesizer_and_opaque_predicates() -> None:
    # Classic OLLVM addition identity: (x ^ y) + 2*(x & y) == x + y
    r1 = simplify_mba_expr("(rcx ^ rdx) + (2 * (rcx & rdx))")
    assert r1["proven"] is True
    assert r1["simplified"] == "(rcx + rdx)"

    # Bitwise OR + AND identity: (x | y) + (x & y) == x + y
    r2 = simplify_mba_expr("(rcx | rdx) + (rcx & rdx)")
    assert r2["proven"] is True
    assert r2["simplified"] == "(rcx + rdx)"

    # Subtraction MBA: (rcx ^ ~rdx) + 1? Wait: (rcx - rdx) = (rcx ^ (-rdx)) + 2 * (rcx & (-rdx))
    r3 = simplify_mba_expr("((rcx ^ rdx) + (2 * (rcx & rdx))) - rdx")
    assert r3["proven"] is True
    assert r3["simplified"] == "rcx"

    op_t = solve_opaque_predicate_z3("(((rcx & (rcx - 1)) == 0) || ((rcx | 1) != 0))")
    assert op_t["is_opaque"] is True
    assert op_t["truth_value"] is True

    op_f = solve_opaque_predicate_z3("((rcx & rdx) > (rcx | rdx))")  # wait: unsigned vs signed; use pure bitwise contradiction:
    op_f2 = solve_opaque_predicate_z3("((rcx ^ rcx) != 0)")
    assert op_f2["is_opaque"] is True
    assert op_f2["truth_value"] is False


def test_v95_cff_dispatcher_with_statement_and_mba_collapse() -> None:
    obf_c = """
int64_t demo_cff_mba(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {
    int64_t st = 10, acc = 0, _k = 0;
L_entry: ;
    if (1) goto L_disp;
L_disp: ;
    _k = st ^ 5;
    if (_k == 15) goto L_arm1;
L_disp2: ;
    if (st == 20) goto L_arm2;
L_arm1: ;
    acc = (rcx ^ rdx) + (2 * (rcx & rdx));
    st = 20;
    if (1) goto L_disp;
L_arm2: ;
    return acc + 1;
}
"""
    clean_c, rep = unflatten_cff_function(obf_c)
    assert rep["cfg_restored"] is True
    assert rep["dispatchers_removed"] >= 1
    assert "(rcx + rdx)" in clean_c
    for vx, vy in ((3, 4), (-10, 25), (100, 200)):
        assert _execute_lifted_c_ast(clean_c, vx, vy, 0, 0) == vx + vy + 1


def test_v95_vm_trace_to_ir_devirtualization_indirect_dispatch() -> None:
    # Synthetic VM-protected x64 function using an indirect jump table dispatch:
    # Base=0x100000:
    #   lea rax, [rip + disp_to_handler] (48 8D 05 xx xx xx xx) -> points to handler at 0x100020
    #   jmp rax                           (FF E0)
    # Handler at +0x20: computes rax = rcx * 2 + rdx + 7; ret
    #   imul rax, rcx, 2                  (48 6B C1 02)
    #   add rax, rdx                      (48 01 D0)
    #   add rax, 7                        (48 83 C0 07)
    #   ret                               (C3)
    buf = bytearray(b"\x90" * 0x40)
    # lea rax, [rip + (0x20 - 7)] -> disp32 = 0x19
    buf[0:7] = bytes.fromhex("48 8D 05 19 00 00 00")
    buf[7:9] = bytes.fromhex("FF E0")
    buf[0x20:0x2B] = bytes.fromhex("48 6B C1 02 48 01 D0 48 83 C0 07")
    buf[0x2B] = 0xC3

    det = detect_vm_dispatchers(bytes(buf), base_va=0x100000, is_64=True)
    assert det["indirect_dispatchers_count"] >= 1

    dev = devirtualize_vm_via_unicorn_trace(
        bytes(buf),
        fn_name="vm_linear_recovered",
        base_va=0x100000,
        is_64=True,
    )
    assert dev["status"] == "complete"
    assert dev["trace_unique_pcs"] >= 6
    clean_c = dev["devirtualized_c"]
    for a, b in ((0, 0), (5, 3), (-4, 10), (42, 13)):
        assert _execute_lifted_c_ast(clean_c, a, b, 0, 0) == (a * 2 + b + 7)


def test_v95_pe_anti_debug_peb_unpacker_and_elf64_unpacker() -> None:
    # 1. Construct minimal PE64 with stub checking PEB->BeingDebugged (gs:[0x60]+2) before writing decoded code to section 2
    pe_buf = bytearray(0x2000)
    pe_buf[0:2] = b"MZ"
    struct.pack_into("<I", pe_buf, 0x3C, 0x80)
    pe_buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe_buf, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)
    opt = 0x98
    struct.pack_into("<H", pe_buf, opt, 0x020B)
    struct.pack_into("<I", pe_buf, opt + 16, 0x1000)
    struct.pack_into("<Q", pe_buf, opt + 24, 0x140000000)
    struct.pack_into("<II", pe_buf, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", pe_buf, opt + 56, 0x3000, 0x200)
    struct.pack_into("<HI", pe_buf, opt + 68, 3, 0x10)
    s0 = opt + 0xF0
    pe_buf[s0 : s0 + 8] = b".stub\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", pe_buf, s0 + 8, 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xE0000020)
    # Sec 1 (.text): VA 0x2000, raw 0x400, size 0x200
    s1 = s0 + 40
    pe_buf[s1 : s1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", pe_buf, s1 + 8, 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0xE0000020)

    # Stub at 0x1000 (file 0x200):
    #   mov rax, gs:[0x60]       (65 48 8B 04 25 60 00 00 00)
    #   movzx eax, byte [rax+2]  (0F B6 40 02)
    #   test eax, eax            (85 C0)
    #   jnz skip_unpack (+disp)  (75 18)
    #   lea rdi, [rip + 0x2000 - cur] -> write `mov eax, 42; ret` (B8 2A 00 00 00 C3) into section .text (VA +0x2000)
    #   let's write absolute/rip-rel to 0x140002000:
    #   lea rdi, [rip + disp]    (48 8D 3D xx xx xx xx) -> at 0x211..0x218 -> target +0x2000: cur VA=0x1018 => disp=0x0FE8
    #   mov dword ptr [rdi], 0x00002AB8 (C7 07 B8 2A 00 00)
    #   mov word ptr [rdi+4], 0xC300    (66 C7 47 04 00 C3)
    #   jmp rdi                         (FF E7)
    # skip_unpack: ret (C3)
    stub = bytearray()
    stub += bytes.fromhex("65 48 8B 04 25 60 00 00 00")  # 9 bytes (0..9)
    stub += bytes.fromhex("0F B6 40 02")                 # 4 bytes (9..13)
    stub += bytes.fromhex("85 C0")                       # 2 bytes (13..15)
    stub += bytes.fromhex("75 15")                       # 2 bytes (15..17) -> skip 21 bytes to 38
    # 17..24: lea rdi, [rip + disp]; rip = 0x1000 + 24 = 0x1018; target=0x2000 -> disp = 0xFE8
    stub += bytes.fromhex("48 8D 3D E8 0F 00 00")
    stub += bytes.fromhex("C7 07 B8 2A 00 00")           # 24..30
    stub += bytes.fromhex("66 C7 47 04 00 C3")           # 30..36
    stub += bytes.fromhex("FF E7")                       # 36..38
    stub += b"\xC3"                                      # 38 (skip_unpack)
    pe_buf[0x200 : 0x200 + len(stub)] = stub

    up_pe = unpack_pe_in_sandbox(bytes(pe_buf))
    assert up_pe["status"] == "unpacked"
    assert up_pe["oep_detected"] is True
    assert up_pe["oep_rva"] == "0x2000"
    assert up_pe["peb_address"] == "0x60010000"

    # 2. Construct minimal ELF64 LE self-modifying stub at 0x401000 jumping to unpacked 0x402000
    elf = bytearray(0x3000)
    # ELF64 header (64 bytes): e_entry = 0x401000, e_phoff = 64, e_phentsize = 56, e_phnum = 1
    elf[0:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIQQQIHHHHHH", elf, 16, 2, 0x3E, 1, 0x401000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    # 1 PT_LOAD RWX covering file 0..0x3000 -> vaddr 0x400000
    struct.pack_into("<IIQQQQQQ", elf, 64, 1, 7, 0, 0x400000, 0x400000, 0x3000, 0x3000, 0x1000)
    # Stub at 0x1000 (VA 0x401000):
    #   lea rdi, [rip + 0x0FF9] (target 0x402000, rip=0x401007 -> disp=0x0FF9)
    #   mov dword ptr [rdi], 0x000007B8
    #   mov word ptr [rdi+4], 0xC300
    #   jmp rdi
    elf_stub = bytes.fromhex("48 8D 3D F9 0F 00 00 C7 07 B8 07 00 00 66 C7 47 04 00 C3 FF E7")
    elf[0x1000 : 0x1000 + len(elf_stub)] = elf_stub

    up_elf = unpack_elf_in_sandbox(bytes(elf))
    assert up_elf["status"] == "unpacked"
    assert up_elf["oep_detected"] is True
    assert up_elf["oep_va"] == "0x402000"
