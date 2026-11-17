"""AetherRE Megazord — Universal Callgraph & CFG Graph Exporter.

Exporta grafos de chamadas (Callgraphs) e grafos de fluxo de controle (CFG)
para renderização em Mermaid (Markdown/Obsidian/GitHub), Graphviz (DOT) e JSON Graph.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from aether_re.engines import disasm, pe_elf, triage
from aether_re.semantic_labeler import enrich_callgraph_nodes

SCHEMA = "callgraph-export.v1"

_CALLGRAPH_CACHE: dict[tuple[str, int, bool], tuple[dict[str, dict[str, Any]], list[tuple[str, str]]]] = {}


def _clean_node_id(raw: str) -> str:
    cleaned = "".join(c if c.isalnum() else "_" for c in raw).strip("_")
    return f"fn_{cleaned}" if cleaned else "fn_unknown"


def extract_callgraph_structure(
    target_path: Path | str,
    *,
    max_nodes: int = 150,
    report_data: dict[str, Any] | None = None,
    deep: bool = False,
) -> tuple[dict[str, dict[str, Any]], list[tuple[str, str]], str | None]:
    """Extrai topologia de nós e arestas do grafo de chamadas a partir de binário ou relatório."""
    p = Path(target_path)
    if not p.is_file():
        raise FileNotFoundError(f"Arquivo alvo não encontrado: {target_path}")

    raw = p.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    magic = triage.detect_magic(raw[:64])
    cache_key = (sha256, max_nodes, deep)
    entry_point: str | None = None

    if not report_data and cache_key in _CALLGRAPH_CACHE:
        pruned_nodes, pruned_edges = _CALLGRAPH_CACHE[cache_key]
        entry_point = next(iter(pruned_nodes.keys()), None)
    else:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[tuple[str, str]] = []

        # 1. Se relatório já foi fornecido ou lido
        if report_data and isinstance(report_data, dict):
            funcs = report_data.get("functions_consensus", [])
            for fn in funcs:
                caller = fn.get("name") or fn.get("address", "sub_unknown")
                if caller not in nodes:
                    nodes[caller] = {
                        "address": fn.get("address", caller),
                        "name": caller,
                        "confidence": fn.get("confidence", 0.8),
                        "calls_count": len(fn.get("calls", [])),
                    }
                for callee in fn.get("calls", []):
                    if callee not in nodes and len(nodes) < max_nodes:
                        nodes[callee] = {
                            "address": callee,
                            "name": callee,
                            "confidence": 0.5,
                            "calls_count": 0,
                        }
                    edges.append((caller, callee))
            entry_point = next(iter(nodes.keys()), None)

        elif deep:
            from aether_re.pipeline import run_megazord
            rep = run_megazord(p, deep=True)
            for fn in rep.functions_consensus:
                caller = fn.name or fn.address
                if caller not in nodes:
                    nodes[caller] = {
                        "address": fn.address,
                        "name": caller,
                        "confidence": fn.confidence,
                        "calls_count": len(fn.calls),
                    }
                for callee in fn.calls:
                    if callee not in nodes and len(nodes) < max_nodes:
                        nodes[callee] = {
                            "address": callee,
                            "name": callee,
                            "confidence": 0.5,
                            "calls_count": 0,
                        }
                    edges.append((caller, callee))
            entry_point = next(iter(nodes.keys()), None)

        else:
            # Extração rápida determinística via estrutura PE/ELF sem travar pipeline
            struct_info = pe_elf.run_structure(raw)
            entry = struct_info.get("entry_point") or "entry_point"
            entry_point = entry
            nodes[entry] = {
                "address": entry,
                "name": entry,
                "confidence": 0.9,
                "calls_count": 0,
            }

            # Conecta chamadas do entry point se houver disasm
            dis_info = disasm.run_disasm(raw, is_64=struct_info.get("is_64", True), file_format=magic)
            for ins in dis_info.get("snippets", []):
                mnem = ins.get("mnemonic", "").lower()
                if mnem in {"call", "jmp"}:
                    target = ins.get("op_str", "").strip()
                    if target and target not in nodes and len(nodes) < max_nodes:
                        nodes[target] = {"address": target, "name": target, "confidence": 0.7, "calls_count": 0}
                        edges.append((entry, target))

            # Adiciona nós para exportações principais
            for exp in struct_info.get("exports", [])[:20]:
                if exp not in nodes and len(nodes) < max_nodes:
                    nodes[exp] = {"address": "export", "name": exp, "confidence": 0.85, "calls_count": 0}

            # Conecta nós de imports representativos
            for imp in struct_info.get("imports", [])[:30]:
                if imp not in nodes and len(nodes) < max_nodes:
                    nodes[imp] = {"address": "import", "name": imp, "confidence": 0.95, "calls_count": 0}
                    edges.append((entry, imp))

        # Limita nós e arestas para renderização limpa
        pruned_nodes = dict(list(nodes.items())[:max_nodes])
        pruned_edges = [
            (src, dst) for src, dst in edges
            if src in pruned_nodes and dst in pruned_nodes
        ][: max_nodes * 3]

        if not report_data:
            _CALLGRAPH_CACHE[cache_key] = (pruned_nodes, pruned_edges)

    return pruned_nodes, pruned_edges, entry_point


_extract_callgraph_structure = extract_callgraph_structure


def export_callgraph(
    target_path: Path | str,
    *,
    output_format: str = "mermaid",
    max_nodes: int = 150,
    report_data: dict[str, Any] | None = None,
    deep: bool = False,
) -> dict[str, Any]:
    """Extrai e exporta o grafo de chamadas de funções para o formato especificado."""
    p = Path(target_path)
    if not p.is_file():
        raise FileNotFoundError(f"Arquivo alvo não encontrado: {target_path}")
    raw = p.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()

    pruned_nodes, pruned_edges, _ = extract_callgraph_structure(
        target_path,
        max_nodes=max_nodes,
        report_data=report_data,
        deep=deep,
    )

    fmt = output_format.lower().strip()
    rendered_content = ""

    # Enriquece nós com rotulação semântica heurística (SymLM style)
    enriched_nodes = enrich_callgraph_nodes(pruned_nodes, pruned_edges)

    if fmt == "mermaid":
        lines = ["flowchart TD"]
        for name, meta in enriched_nodes.items():
            nid = _clean_node_id(name)
            label = meta.get("suggested_label") or name
            safe_label = label.replace('"', '\\"')
            lines.append(f'    {nid}["{safe_label}"]')
        for src, dst in pruned_edges:
            nid_src = _clean_node_id(src)
            nid_dst = _clean_node_id(dst)
            lines.append(f"    {nid_src} --> {nid_dst}")
        rendered_content = "\n".join(lines) + "\n"

    elif fmt == "dot":
        lines = ['digraph CallGraph {', '    rankdir=LR;', '    node [shape=box, style=rounded, fontname="Helvetica"];']
        for name, meta in enriched_nodes.items():
            nid = _clean_node_id(name)
            label = meta.get("suggested_label") or name
            safe_label = label.replace('"', '\\"')
            lines.append(f'    {nid} [label="{safe_label}"];')
        for src, dst in pruned_edges:
            nid_src = _clean_node_id(src)
            nid_dst = _clean_node_id(dst)
            lines.append(f"    {nid_src} -> {nid_dst};")
        lines.append("}")
        rendered_content = "\n".join(lines) + "\n"

    elif fmt == "json":
        graph_obj = {
            "schema": "source-graph.v1",
            "nodes": [{"id": name, "label": meta.get("suggested_label") or name, **meta} for name, meta in enriched_nodes.items()],
            "edges": [{"source": src, "target": dst} for src, dst in pruned_edges],
        }
        rendered_content = json.dumps(graph_obj, indent=2, ensure_ascii=False) + "\n"

    else:
        raise ValueError(f"Formato não suportado: {output_format}. Use 'mermaid', 'dot' ou 'json'.")

    return {
        "schema": SCHEMA,
        "status": "complete",
        "target": str(p.resolve()),
        "target_sha256": sha256,
        "format": fmt,
        "nodes_count": len(pruned_nodes),
        "edges_count": len(pruned_edges),
        "graph_content": rendered_content,
        "limitations": [
            "grafo gerado a partir de chamadas estáticas e símbolos observados",
            "chamadas dinâmicas ou indiretas ofuscadas não resolvidas são excluídas do grafo determinístico",
        ],
    }
