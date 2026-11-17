"""Mapeia fases F00--F12 para arquivos de teste por CONTEUDO (imports reais).

Metodo auditavel: cada arquivo de teste declara quais modulos de ``aether_re``
importa; cada modulo tem uma fase atribuida no mapa curado abaixo. A fase de um
arquivo de teste e a uniao das fases dos modulos que ele importa de fato.

Nao executa testes. Nao promove gates. Apenas deriva o mapa e as contagens
observadas no JUnit informado.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path

PHASES = tuple(f"F{index:02d}" for index in range(13))

# Mapa curado modulo -> fase, derivado das definicoes das fases em
# docs/PLANO_MESTRE_ENGENHARIA_FORENSE_2026-09-15.md (secoes F00..F12).
MODULE_PHASE: dict[str, str] = {
    # F00 -- preservacao, escopo e ambiente reproduzivel
    "custody": "F00", "custody_release": "F00", "doctor": "F00",
    "project_snapshot": "F00", "project_inventory": "F00", "repro_package": "F00",
    "safe_walk": "F00", "archive_intake": "F00", "test_runner": "F00",
    "toolchain_lock": "F00", "unpackers": "F00", "dia_build": "F00",
    "ghidra_runtime_lock": "F00",
    "frame_relocation": "F05", "frame_arena_runtime": "F05", "frame_arena_program": "F05",
    "native_leaf_data": "F05", "native_caller_data": "F05",
    # F01 -- corrigir a verdade do pipeline
    "pipeline": "F01", "models": "F01", "ir": "F01", "ir_graph": "F01",
    "static_profiles": "F01", "static_worker": "F01", "profile_router": "F01",
    "graph_store": "F01",
    # F02 -- contratos, custodia e runtime governado
    "contracts": "F02", "evidence": "F02", "evidence_contract": "F02", "native_memory_custody": "F02",
    "evidence_journal": "F02", "evidence_store": "F02", "kernel_contracts": "F02",
    "lock": "F02", "cache": "F02", "checkpoint": "F02", "process": "F02",
    "intake": "F02", "validation_campaign": "F02",
    # F03 -- corpus e oraculos independentes
    "corpus": "F03", "corpus_eval": "F03", "corpus_registry": "F03",
    # F04 -- leitura semantica de projetos
    "source": "F04", "c_source": "F04", "c_semantic": "F04",
    "build_audit": "F04", "project_audit": "F04", "language_profiles": "F04",
    "rea_static": "F04",
    # F05 -- engenharia reversa estrutural de binarios
    "pe_debug": "F05", "pdb_dia": "F05", "jar_worker": "F05", "indirect_effects": "F05",
    "firmware_layout": "F05", "profile_comparison": "F05",
    "capabilities": "F05", "graph_export": "F05", "pointer_provenance": "F05", "stack_parameters": "F05",
    "frame_derivation": "F05", "frame_usage": "F05", "frame_conservation": "F05",
    "frame_runtime": "F05", "frame_program": "F05",
    "frame_request": "F05", "universal_frame": "F05", "native_frame_address": "F05", "native_frame_request": "F05",
    # F06 -- fonte <-> build <-> binario <-> comportamento
    "correlation": "F06", "build_link": "F06", "differential": "F06",
    "behavioral_runner": "F06", "profile_scope": "F06", "binary_diff": "F06",
    # F07 -- auditoria forense, riscos e dependencias
    "risk_audit": "F07", "taint_audit": "F07", "dependency_audit": "F07",
    "project_dependencies": "F07", "sarif": "F07", "forensic_rules": "F07",
    # F08 -- laboratorio dinamico e traces
    "dynamic_effects": "F08", "dynamic_lab_contracts": "F08", "lab_policy": "F08",
    "trace": "F08", "trace_correlation": "F08", "windows_sandbox_guest": "F08",
    "hyperv_preflight": "F08", "hyperv_observation": "F08", "strace_import": "F08",
    # F09 -- fuzzing, simbolico e equivalencia limitada
    "fuzz": "F09", "symbolic": "F09", "ghidra_pcode_c": "F05", "native_memory": "F05", "observed_calls": "F05", "high_parameters": "F05", "call_closure": "F05", "call_runtime": "F05", "effect_trace": "F05", "stack_liveness": "F05",
    # F10 -- consenso calibrado e avaliacao cega
    "metrics": "F10", "benchmark": "F10",
    # F11 -- inteligencia assistida e revisao
    "assistant": "F11", "claims": "F11", "review_ui": "F11",
    "mcp_server": "F11",
    # F12 -- homologacao independente e operacao
    "documentation": "F12", "external_attestations": "F12",
    "ghidra_provenance": "F12", "homologation": "F12",
    "phase_gates": "F12", "profile_certification": "F12",
    "release_builder": "F12", "release_certification": "F12",
    "release_inventory": "F12",
    # adapters e engines (resolvidos pelo nome-folha do modulo)
    "adapters": "F01", "native_normalize": "F01", "triage": "F01",
    "strings_decode": "F01",
    "ghidra": "F05", "ghidra_parse": "F05", "ghidra_headless_bridge": "F05", "ghidra_pcode_ir": "F05", "rizin": "F05", "angr": "F05",
    "unicorn_emu": "F05", "binaryninja": "F05", "ilspy": "F05", "jvm": "F05",
    "android": "F05", "wasm": "F05", "macho": "F05", "firmware": "F05",
    "dwarf": "F05", "pe_elf": "F05", "disasm": "F05", "elf_calls": "F05",
    "decompiler": "F05",
    "reconstruct": "F06",
    "consensus": "F10", "comparative_report": "F10",
    "frida_dyn": "F08",
    # Motores SOTA integrados (Reverse Engineering Graph)
    "calling_convention": "F05",
    "cfg_dominance": "F05",
    "deobfuscator": "F05",
    "function_simhash": "F06",
    "graph_alignment": "F06",
    "graph_analytics": "F05",
    "operand_norm": "F01",
    "packer_detect": "F05",
    "pdg_taint": "F07",
    "semantic_labeler": "F04",
    "struct_recovery": "F05",
    "symbolic_constraints": "F09",
    "crypto_detect": "F05", "golang_recover": "F05",
    "authenticode_audit": "F05", "dwarf_types": "F05",
    "macho_forensics": "F05", "rust_recover": "F05",
    "firmware_forensics": "F05", "python_forensics": "F05",
    "cpp_rtti": "F05", "api_hash_resolve": "F05", "dotnet_forensics": "F05",
    "floss_strings": "F05",
    "ole_macro": "F05", "kernel_driver_audit": "F05", "vmlinux_extract": "F05",
    "dex_forensics": "F05", "wasm_forensics": "F05",
    "cfi_gadget_audit": "F05", "installer_forensics": "F05", "omni_audit": "F05",
    "ctree_structuring": "F05", "ssa_ir": "F05", "til_engine": "F05",
    "memory_forensics": "F08", "minidump_parser": "F08",
    "semantic_deobfuscator": "F05", "smt_solver": "F09",
    "ground_truth_eval": "F10", "c_equivalence": "F09",
}

_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+aether_re(?:\.([A-Za-z_][\w.]*))?", re.M)


def modules_imported(source: str) -> set[str]:
    """Return the ``aether_re`` submodule paths imported by ``source``."""
    found: set[str] = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return found
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("aether_re"):
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("aether_re"):
                for alias in node.names:
                    found.add(f"{node.module}.{alias.name}")
                found.add(node.module)
    # Fallback textual conservador para imports dinamicos/comentados.
    for match in _IMPORT_RE.finditer(source):
        suffix = match.group(1)
        found.add(f"aether_re.{suffix}" if suffix else "aether_re")
    return found


def leaf_module(dotted: str) -> str:
    parts = dotted.split(".")
    # aether_re.<mod> | aether_re.engines.<mod> | aether_re.adapters.<mod>
    if len(parts) >= 3 and parts[1] in {"engines", "adapters"}:
        return parts[2]
    if len(parts) >= 2:
        return parts[1]
    return ""


def build_map(root: Path) -> dict[str, object]:
    tests_dir = root / "tests"
    by_phase: dict[str, list[str]] = {phase: [] for phase in PHASES}
    unmapped_modules: set[str] = set()
    per_file: dict[str, dict[str, object]] = {}

    for path in sorted(tests_dir.glob("test_*.py")):
        source = path.read_text(encoding="utf-8", errors="replace")
        imported = modules_imported(source)
        leaves = {leaf_module(item) for item in imported if leaf_module(item)}
        phases: set[str] = set()
        for leaf in leaves:
            phase = MODULE_PHASE.get(leaf)
            if phase:
                phases.add(phase)
            elif leaf and not leaf.startswith("_"):
                unmapped_modules.add(leaf)
        if not phases:
            phases.add("F00")  # infraestrutura/CLI sem modulo dedicado
            per_file[path.name] = {"phases": ["F00"], "fallback": True,
                                   "modules": sorted(leaves)}
        else:
            per_file[path.name] = {"phases": sorted(phases), "fallback": False,
                                   "modules": sorted(leaves)}
        for phase in phases:
            by_phase[phase].append(f"tests/{path.name}")

    return {
        "schema": "phase-test-map.v1",
        "method": "fase do arquivo de teste = uniao das fases dos modulos aether_re "
                  "efetivamente importados (AST); fallback F00 quando nao ha import",
        "phases": {phase: sorted(files) for phase, files in by_phase.items()},
        "files": per_file,
        "counts": {phase: len(files) for phase, files in by_phase.items()},
        "unmapped_modules": sorted(unmapped_modules),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    mapping = build_map(Path(args.root))
    Path(args.out).write_text(
        json.dumps(mapping, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(json.dumps(mapping["counts"], indent=2, ensure_ascii=False))
    print("arquivos de teste mapeados:", len(mapping["files"]))
    print("modulos sem fase atribuida:", mapping["unmapped_modules"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
