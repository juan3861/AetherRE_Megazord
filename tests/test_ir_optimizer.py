"""Unit tests for Phase II CFG + Dataflow/SSA IR Optimizer (`aether_re.ir_optimizer`)."""

from __future__ import annotations

from aether_re.ir_optimizer import optimize_lifted_c_via_ssa
from aether_re.project_reconstructor import _execute_lifted_c_ast


def test_dead_flag_and_dead_assign_elimination() -> None:
    raw = "\n".join([
        "int64_t demo_dead(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_1000: ; /* xor r13d, r13d */",
        "    r13 = 0;",
        "L_1003: ; /* add rax, 5 */",
        "    rax = (int64_t)((rcx) + (5)); cmp_lhs = rax; cmp_rhs = 0;",
        "L_1008: ; /* dead rbx */",
        "    rbx = (int64_t)(aether_u32(aether_u32(rdx)));",
        "L_100c: ; /* mov rdx, r13 */",
        "    r14 = (int64_t)(r13);",
        "L_1010: ; /* add rax, r14 */",
        "    rax = (int64_t)((rax) + (r14));",
        "    return rax;",
        "}",
    ])
    opt, metrics = optimize_lifted_c_via_ssa(raw)
    assert metrics["dead_flags_removed"] >= 2
    assert metrics["dead_assigns_removed"] >= 1
    body_text = "\n".join(opt.splitlines()[6:])
    assert "cmp_lhs" not in body_text
    assert "rbx =" not in body_text
    assert "r13 =" not in body_text
    assert "r14 =" not in body_text
    # Semantic parity preserved
    for v in (0, 1, -7, 42):
        assert _execute_lifted_c_ast(raw, v, 99, 0, 0) == _execute_lifted_c_ast(opt, v, 99, 0, 0)


def test_kildall_loop_const_safety_and_dead_branch_folding() -> None:
    raw = "\n".join([
        "int64_t demo_loop(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_2000: ; /* init */",
        "    rax = 0;",
        "    rbx = 1;",
        "    cmp_lhs = (int64_t)(rbx); cmp_rhs = 0;",
        "    if (cmp_lhs == cmp_rhs) goto L_2030;",
        "L_2010: ; /* loop */",
        "    cmp_lhs = (int64_t)(rax); cmp_rhs = (int64_t)(rcx);",
        "    if (cmp_lhs >= cmp_rhs) goto L_2040;",
        "    rax = (int64_t)((rax) + (rbx));",
        "    if (1) goto L_2010;",
        "L_2030: ; /* dead branch */",
        "    rax = 999;",
        "L_2040: ; /* exit */",
        "    return rax;",
        "}",
    ])
    opt, _ = optimize_lifted_c_via_ssa(raw)
    assert "999" not in opt
    for n in (0, 1, 5, 12):
        assert _execute_lifted_c_ast(raw, n, 0, 0, 0) == _execute_lifted_c_ast(opt, n, 0, 0, 0) == max(0, n)


def test_stack_slot_mem2reg_promotion_and_escape_safety() -> None:
    safe_raw = "\n".join([
        "int64_t demo_stack_safe(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_3000: ; /* frame */",
        "    rbp = rsp;",
        "    rsp = (int64_t)((rsp) - (64));",
        "    aether_mem_write(rbp - 0x10, 8, rcx);",
        "    aether_mem_write(rbp - 0x18, 4, 10);",
        "    rax = (int64_t)(aether_mem_read(rbp - 0x10, 8));",
        "    rbx = aether_u32(aether_mem_read(rbp - 0x18, 4));",
        "    rax = (int64_t)((rax) + (rbx));",
        "    return rax;",
        "}",
    ])
    opt_safe, m_safe = optimize_lifted_c_via_ssa(safe_raw)
    assert m_safe["stack_slots_promoted"] == 2
    assert "aether_mem_read" not in opt_safe
    assert "aether_mem_write" not in opt_safe
    for v in (0, 7, -3, 100):
        assert _execute_lifted_c_ast(safe_raw, v, 0, 0, 0) == _execute_lifted_c_ast(opt_safe, v, 0, 0, 0) == v + 10

    escaped_raw = "\n".join([
        "int64_t demo_stack_escaped(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_4000: ; /* escaped rbp */",
        "    rbp = rsp;",
        "    rsp = (int64_t)((rsp) - (64));",
        "    aether_mem_write(rbp - 0x10, 8, rcx);",
        "    rdx = (int64_t)(rbp - 0x10);",
        "    rax = (int64_t)(aether_mem_read(rdx, 8));",
        "    return rax;",
        "}",
    ])
    opt_esc, m_esc = optimize_lifted_c_via_ssa(escaped_raw)
    assert m_esc["stack_slots_promoted"] == 0
    assert "aether_mem_write(" in opt_esc
    assert "0x10" in opt_esc
    assert _execute_lifted_c_ast(escaped_raw, 42, 0, 0, 0) == _execute_lifted_c_ast(opt_esc, 42, 0, 0, 0) == 42

    # Incoming Win64 stack arg above prolog frame (`[rsp + 0xa0]` when frame is `0x58` bytes) must NOT promote
    stack_arg_raw = "\n".join([
        "int64_t demo_win64_stack_arg(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "L_5000: ; /* frame */",
        "    rsp = (int64_t)((rsp) - (88));",
        "    aether_mem_write(rsp + 0x48, 8, rcx);",
        "    rax = (int64_t)(aether_mem_read(rsp + 0xa0, 8));",
        "    rbx = (int64_t)(aether_mem_read(rsp + 0x48, 8));",
        "    rax = (int64_t)((rax) + (rbx));",
        "    return rax;",
        "}",
    ])
    opt_sa, m_sa = optimize_lifted_c_via_ssa(stack_arg_raw)
    assert m_sa["stack_slots_promoted"] == 1
    assert "aether_mem_read(rsp + 0xa0" in opt_sa
    assert "aether_mem_write" not in opt_sa
    assert "(rax) + (rcx)" in opt_sa or "rcx" in opt_sa
