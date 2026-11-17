from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from aether_re.ctree_structuring import structure_control_flow
from aether_re.til_engine import lookup_til_api, lookup_til_struct, match_struct_by_field_offsets
from aether_re.ssa_ir import lift_to_ssa_ir
from aether_re.smt_solver import solve_constraints_smt
from aether_re.memory_forensics import analyze_memory_regions


def test_gear1_ctree_structuring():
    nodes = ["entry", "loop_head", "loop_body", "loop_exit", "ret_node"]
    edges = [
        ("entry", "loop_head"),
        ("loop_head", "loop_body"),
        ("loop_body", "loop_head"),  # natural loop back-edge
        ("loop_head", "loop_exit"),
        ("loop_exit", "ret_node"),
    ]
    idom = {
        "entry": None,
        "loop_head": "entry",
        "loop_body": "loop_head",
        "loop_exit": "loop_head",
        "ret_node": "loop_exit",
    }
    loops = [{"header": "loop_head", "tail": "loop_body", "nodes": ["loop_head", "loop_body"]}]
    
    semantics = {
        "entry": {"statements": [], "terminator": {"kind": "jump", "target": "loop_head"}},
        "loop_head": {"statements": [], "terminator": {"kind": "branch", "condition": "i < 3", "true": "loop_body", "false": "loop_exit"}},
        "loop_body": {"statements": ["i++;"], "terminator": {"kind": "jump", "target": "loop_head"}},
        "loop_exit": {"statements": [], "terminator": {"kind": "jump", "target": "ret_node"}},
        "ret_node": {"statements": [], "terminator": {"kind": "return", "value": None}},
    }
    res = structure_control_flow(nodes, edges, idom, loops, "entry", block_semantics=semantics,
                                 function_signature="void recovered_function_entry(void)", declarations=["int i = 0;"])
    assert res["schema"] == "ctree-structuring-report.v2"
    assert res["status"] == "complete"
    assert res["natural_loops_structured"] == 1
    assert res["goto_elimination_rate_pct"] == 100.0
    assert "while (" in res["structured_c_source"]
    assert "void recovered_function_entry(void)" in res["structured_c_source"]
    assert "i < 3" in res["structured_c_source"]


def test_gear2_til_engine():
    # Lookup API
    api = lookup_til_api("kernel32.dll:CreateFileW")
    assert api is not None
    assert api["return_type"] == "HANDLE"
    assert len(api["params"]) == 7

    # Lookup Struct
    s = lookup_til_struct("STARTUPINFOW")
    assert s is not None
    assert s["size_64"] == 104
    assert s["fields"][0x28]["name"] == "dwXSize"

    # Match by offsets
    matched = match_struct_by_field_offsets([0x00, 0x08, 0x10], os_filter="windows")
    assert len(matched) >= 1
    assert any(m["struct_name"] == "SECURITY_ATTRIBUTES" for m in matched)


def test_gear3_ssa_ir():
    insns = [
        {"mnemonic": "mov", "op_str": "rax, 10"},
        {"mnemonic": "add", "op_str": "rax, rbx"},
        {"mnemonic": "cmp", "op_str": "rax, 20"},
        {"mnemonic": "je", "op_str": "block1"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    cfg_edges = [("entry", "block1"), ("entry", "block2"), ("block1", "merge"), ("block2", "merge")]
    for item in insns:
        item["block"] = "entry"
    insns[-1]["block"] = "merge"
    
    res = lift_to_ssa_ir(insns, cfg_edges=cfg_edges, entry="entry")
    assert res["schema"] == "ssa-ir-report.v1"
    assert res["total_lifted_instructions"] == 5
    assert res["status"] == "complete"
    # A join is not itself a competing definition. Both paths carry the
    # same value defined in entry; manufacturing phi_var would be false SSA.
    assert res["phi_nodes_count"] == 0
    assert any(i["op"] == "ASSIGN" for i in res["ssa_instructions"])
    assert any(i["op"] == "BINOP_ADD" for i in res["ssa_instructions"])


def test_gear5_smt_solver_z3():
    # SAT test: x > 10, x < 20, x * 2 == 30 -> x = 15
    constraints = ["x > 10", "x < 20"]
    res = solve_constraints_smt(constraints)
    assert res["status"] == "SAT", res
    assert res["is_satisfiable"] is True
    assert 10 < res["model"]["x"] < 20

    # UNSAT test: x > 10 and x < 5
    unsat_res = solve_constraints_smt(["x > 10", "x < 5"])
    assert unsat_res["status"] == "UNSAT", unsat_res
    assert unsat_res["is_satisfiable"] is False


def test_gear6_memory_forensics():
    # Fake VAD regions
    regions = [
        {
            "base_address": 0x7FFF0000,
            "size": 4096,
            "protection": "PAGE_EXECUTE_READWRITE",
            "state": "MEM_COMMIT",
            "data": b"MZ" + b"\x00" * 62,  # Reflected PE
        },
        {
            "base_address": 0x10000000,
            "size": 8192,
            "protection": "PAGE_READONLY",
            "state": "MEM_COMMIT",
            "data": b"NORMAL_DATA" * 10,
        },
    ]
    res = analyze_memory_regions(regions)
    assert res["schema"] == "memory-forensics-report.v1"
    assert res["is_compromised_or_unpacked"] is True
    assert res["rwx_regions_count"] == 1
    assert res["injected_pe_count"] == 1
    assert res["rwx_regions"][0]["protection"] == "PAGE_EXECUTE_READWRITE"
