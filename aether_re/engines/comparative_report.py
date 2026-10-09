"""Geração de relatórios comparativos entre fontes do consenso."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from aether_re.models import AnalysisReport, FunctionEvidence
from aether_re.engines.consensus import _source_agreement


def export_function_comparison_csv(report: AnalysisReport, path: Path) -> None:
    """Exporta uma tabela CSV com dados por função e por fonte."""
    fieldnames = [
        "address",
        "name",
        "sources",
        "confidence",
        "evidence_quality",
        "source_agreement",
        "coverage",
        "selected_source",
        "calls_count",
        "imports_count",
        "strings_count",
        "warnings",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for func in report.merged_functions:
            writer.writerow(
                {
                    "address": func.address,
                    "name": func.name,
                    "sources": ",".join(func.sources),
                    "confidence": round(func.confidence, 4),
                    "evidence_quality": round(func.evidence_quality, 4),
                    "source_agreement": round(func.source_agreement, 4),
                    "coverage": round(func.coverage, 4),
                    "selected_source": func.selected_source,
                    "calls_count": len(func.calls),
                    "imports_count": len(func.imports_used),
                    "strings_count": len(func.strings_near),
                    "warnings": "; ".join(func.warnings),
                }
            )


def compute_source_agreement_matrix(report: AnalysisReport) -> dict[str, dict[str, float]]:
    """Calcula a taxa de concordância entre cada par de fontes."""
    pairs: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for func in report.merged_functions:
        sources = func.sources
        if len(sources) < 2:
            continue
        for i, a in enumerate(sources):
            for b in sources[i + 1:]:
                left = func.evidence.get(a)
                right = func.evidence.get(b)
                if left is None or right is None:
                    continue
                pair_score = _source_agreement(FunctionEvidence(**left), FunctionEvidence(**right))
                pairs[a][b].append(pair_score)
                pairs[b][a].append(pair_score)

    matrix: dict[str, dict[str, float]] = {}
    for a, b_map in pairs.items():
        matrix[a] = {}
        for b, values in b_map.items():
            matrix[a][b] = round(sum(values) / len(values), 4) if values else 0.0
    return matrix


def find_divergent_functions(
    report: AnalysisReport,
    threshold: float = 0.5,
) -> list[dict[str, Any]]:
    """Encontra funções onde as fontes discordam significativamente."""
    divergent = []
    for func in report.merged_functions:
        if func.source_agreement < threshold:
            divergent.append(
                {
                    "address": func.address,
                    "name": func.name,
                    "sources": func.sources,
                    "source_agreement": round(func.source_agreement, 4),
                    "confidence": round(func.confidence, 4),
                    "warnings": func.warnings,
                    "evidence": {
                        src: {
                            "name": item.get("name", ""),
                            "calls": item.get("calls", []),
                            "imports_used": item.get("imports_used", []),
                        }
                        for src, item in func.evidence.items()
                    },
                }
            )
    return divergent


def generate_comparative_report(
    report: AnalysisReport,
    out_dir: Path,
) -> dict[str, str]:
    """Gera todos os artefatos comparativos em um diretório."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}

    csv_path = out_dir / "function_comparison.csv"
    export_function_comparison_csv(report, csv_path)
    paths["csv"] = str(csv_path)

    matrix = compute_source_agreement_matrix(report)
    matrix_path = out_dir / "source_agreement_matrix.json"
    matrix_path.write_text(
        json.dumps(matrix, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    paths["matrix"] = str(matrix_path)

    divergent = find_divergent_functions(report)
    divergent_path = out_dir / "divergent_functions.json"
    divergent_path.write_text(
        json.dumps(divergent, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    paths["divergent"] = str(divergent_path)

    return paths
