"""Unit tests for Reverse Engineering Graph — Program Dependence Graph & Taint Slicing."""

from __future__ import annotations

import pytest

from aether_re.pdg_taint import (
    SCHEMA,
    _parse_def_use,
    build_program_dependence_graph,
    compute_taint_slice,
)


def test_parse_def_use():
    defs, uses = _parse_def_use("mov", "eax, ebx")
    assert "eax" in defs
    assert "ebx" in uses

    defs, uses = _parse_def_use("add", "ecx, edx")
    assert "ecx" in defs
    assert "ecx" in uses
    assert "edx" in uses


def test_build_pdg_data_dependencies():
    insns = [
        {"id": "i0", "mnemonic": "mov", "op_str": "eax, 0x10"},
        {"id": "i1", "mnemonic": "add", "op_str": "eax, 0x20"},
        {"id": "i2", "mnemonic": "mov", "op_str": "ebx, eax"},
    ]
    pdg = build_program_dependence_graph(insns)
    deps = pdg["data_dependencies"]
    assert len(deps) >= 2
    # i0 defines eax, i1 uses eax
    assert any(d["source"] == "i0" and d["target"] == "i1" and d["variable"] == "eax" for d in deps)
    # i1 defines eax, i2 uses eax
    assert any(d["source"] == "i1" and d["target"] == "i2" and d["variable"] == "eax" for d in deps)


def test_taint_slice_vulnerable_path():
    # recv -> buf -> rdi -> system (vulnerabilidade clássica)
    insns = [
        {"id": "i0", "mnemonic": "call", "op_str": "recv"},
        {"id": "i1", "mnemonic": "mov", "op_str": "rdi, rax"},
        {"id": "i2", "mnemonic": "call", "op_str": "system"},
    ]
    res = compute_taint_slice(insns)
    assert res["schema"] == SCHEMA
    assert res["is_vulnerable"] is True
    assert res["initial_sources_count"] >= 1
    assert res["reached_sinks_count"] >= 1
    assert res["reached_sinks"][0]["sink_name"] == "system"


def test_taint_slice_safe_isolated_path():
    # getenv isolado sem chegar a nenhum sink
    insns = [
        {"id": "i0", "mnemonic": "call", "op_str": "getenv"},
        {"id": "i1", "mnemonic": "mov", "op_str": "rbx, rax"},
        {"id": "i2", "mnemonic": "add", "op_str": "rbx, 1"},
        {"id": "i3", "mnemonic": "ret", "op_str": ""},
    ]
    res = compute_taint_slice(insns)
    assert res["is_vulnerable"] is False
    assert res["reached_sinks_count"] == 0
