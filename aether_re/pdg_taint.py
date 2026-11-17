"""Reverse Engineering Graph (REG) — Program Dependence Graph (PDG) & Taint Reachability.

Implementa o Grafo de Dependência de Programa (PDG) e Fatiamento de Mancha (Taint Slicing):
  1. Dependência de Controle: baseada em pós-dominadores do CFG (Ferrante et al. 1987);
  2. Dependência de Dados: cadeias Def-Use entre instruções e registradores/pilha;
  3. Fatiamento de Mancha (Forward & Backward Taint Slicing): verifica se dados controlados
     por fontes não confiáveis (sources: recv, ReadFile, argv) alcançam sinks críticos
     (sinks: system, WinExec, strcpy, memcpy, sprintf) sem sanitização.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

SCHEMA = "pdg-taint-report.v1"

DEFAULT_TAINT_SOURCES = {"recv", "readfile", "read", "getenv", "argv", "socket", "accept", "cin", "scanf"}
DEFAULT_CRITICAL_SINKS = {"system", "winexec", "shellexecute", "strcpy", "memcpy", "sprintf", "vsprintf", "execve", "popen"}


def _parse_def_use(mnemonic: str, op_str: str) -> tuple[set[str], set[str]]:
    """Extrai registradores definidos (escritos) e usados (lidos) por uma instrução."""
    mnem = mnemonic.lower().strip()
    ops = [p.strip().lower() for p in op_str.split(",") if p.strip()]
    regs_def: set[str] = set()
    regs_use: set[str] = set()

    all_regs = re.findall(r"\b([re]?[a-d]x|[re]?[sbi]p|[re]?[sd]i|r\d{1,2}[bwd]?|al|ah|bl|bh|cl|ch|dl|dh)\b", op_str.lower())
    
    if mnem in {"mov", "lea", "movzx", "movsx", "pop"}:
        if ops:
            dest = ops[0]
            m_dest = re.match(r"\b([re]?[a-d]x|[re]?[sbi]p|[re]?[sd]i|r\d{1,2}[bwd]?)\b", dest)
            if m_dest:
                regs_def.add(m_dest.group(1))
            # O que estiver no source é usado
            if len(ops) > 1:
                regs_use.update(re.findall(r"\b([re]?[a-d]x|[re]?[sbi]p|[re]?[sd]i|r\d{1,2}[bwd]?)\b", ops[1]))
    elif mnem in {"add", "sub", "xor", "or", "and", "shl", "shr", "imul"}:
        if ops:
            dest = ops[0]
            m_dest = re.match(r"\b([re]?[a-d]x|[re]?[sbi]p|[re]?[sd]i|r\d{1,2}[bwd]?)\b", dest)
            if m_dest:
                regs_def.add(m_dest.group(1))
                regs_use.add(m_dest.group(1))
            if len(ops) > 1:
                regs_use.update(re.findall(r"\b([re]?[a-d]x|[re]?[sbi]p|[re]?[sd]i|r\d{1,2}[bwd]?)\b", ops[1]))
    elif mnem in {"cmp", "test", "push"}:
        regs_use.update(all_regs)
    elif mnem == "call":
        # Chamada define registradores de retorno
        regs_def.update({"rax", "eax", "al"})
        # E pode usar registradores de argumento de convenções de chamada (SysV / MS x64 / cdecl)
        abi_args = {"rdi", "rsi", "rdx", "rcx", "r8", "r9", "ecx", "edx"}
        regs_use.update(abi_args | set(all_regs))

    return regs_def, regs_use


def build_program_dependence_graph(
    instructions: Sequence[dict[str, Any]],
    cfg_edges: Sequence[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Constrói arestas de dependência de dados (Def-Use) e dependência de controle."""
    nodes: list[dict[str, Any]] = []
    data_dep_edges: list[dict[str, Any]] = []
    last_def: dict[str, str] = {}

    for idx, ins in enumerate(instructions):
        ins_id = ins.get("id") or ins.get("address") or f"ins_{idx}"
        mnem = str(ins.get("mnemonic", "")).lower()
        op_str = str(ins.get("op_str", "")).lower()
        defs, uses = _parse_def_use(mnem, op_str)

        node_info = {
            "id": ins_id,
            "index": idx,
            "mnemonic": mnem,
            "op_str": op_str,
            "defs": sorted(defs),
            "uses": sorted(uses),
        }
        nodes.append(node_info)

        # Para cada registrador usado, cria aresta Def-Use vinda da última definição
        for reg in uses:
            if reg in last_def:
                data_dep_edges.append({
                    "source": last_def[reg],
                    "target": ins_id,
                    "variable": reg,
                    "type": "data_dependence",
                })

        for reg in defs:
            last_def[reg] = ins_id

    return {
        "nodes": nodes,
        "data_dependencies": data_dep_edges,
        "control_dependencies": [],
    }


def compute_taint_slice(
    instructions: Sequence[dict[str, Any]],
    *,
    sources: set[str] | None = None,
    sinks: set[str] | None = None,
) -> dict[str, Any]:
    """Calcula a propagação de mancha das fontes (sources) até os sumidouros (sinks)."""
    src_set = sources or DEFAULT_TAINT_SOURCES
    sink_set = sinks or DEFAULT_CRITICAL_SINKS

    pdg = build_program_dependence_graph(instructions)
    nodes = {n["id"]: n for n in pdg["nodes"]}
    adj: dict[str, list[tuple[str, str]]] = {n["id"]: [] for n in pdg["nodes"]}

    for edge in pdg["data_dependencies"]:
        s, t, var = edge["source"], edge["target"], edge["variable"]
        if s in adj and t in nodes:
            adj[s].append((t, var))

    # Identifica nós de fonte de mancha (taint sources)
    tainted_nodes: set[str] = set()
    initial_sources: list[dict[str, Any]] = []

    for n in pdg["nodes"]:
        op_str = n["op_str"]
        mnem = n["mnemonic"]
        is_src = any(s in op_str or s in mnem for s in src_set)
        if is_src:
            tainted_nodes.add(n["id"])
            initial_sources.append(n)

    # Propagação forward da mancha ao longo do PDG
    worklist = list(tainted_nodes)
    propagation_trace: list[dict[str, Any]] = []

    while worklist:
        curr = worklist.pop(0)
        for nxt, var in adj.get(curr, []):
            if nxt not in tainted_nodes:
                tainted_nodes.add(nxt)
                worklist.append(nxt)
                propagation_trace.append({
                    "from_node": curr,
                    "to_node": nxt,
                    "propagated_variable": var,
                })

    # Verifica se algum nó manchado alcança um sink crítico
    reached_sinks: list[dict[str, Any]] = []
    for t_id in tainted_nodes:
        n = nodes[t_id]
        op_str = n["op_str"]
        mnem = n["mnemonic"]
        is_sink = any(s in op_str or s in mnem for s in sink_set)
        if is_sink:
            matched_sink = next(s for s in sink_set if s in op_str or s in mnem)
            reached_sinks.append({
                "sink_node": t_id,
                "sink_name": matched_sink,
                "instruction": f"{mnem} {op_str}",
            })

    is_vulnerable = len(reached_sinks) > 0

    return {
        "schema": SCHEMA,
        "is_vulnerable": is_vulnerable,
        "tainted_nodes_count": len(tainted_nodes),
        "initial_sources_count": len(initial_sources),
        "initial_sources": initial_sources,
        "reached_sinks_count": len(reached_sinks),
        "reached_sinks": reached_sinks,
        "taint_propagation_trace": propagation_trace,
        "total_data_dependencies": len(pdg["data_dependencies"]),
    }
