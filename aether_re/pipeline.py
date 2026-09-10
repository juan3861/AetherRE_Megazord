"""Pipeline principal do Megazord — engines nativas + ensemble por função."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aether_re.adapters.angr import AngrAdapter
from aether_re.adapters.binaryninja import BinaryNinjaAdapter
from aether_re.adapters.frida_dyn import FridaAdapter
from aether_re.adapters.ghidra import GhidraAdapter
from aether_re.adapters.rizin import RizinAdapter
from aether_re.adapters.unicorn_emu import UnicornAdapter
from aether_re.engines import disasm, pe_elf, reconstruct, strings_decode, triage
from aether_re.engines.comparative_report import generate_comparative_report
from aether_re.engines.consensus import (
    compute_overall_confidence,
    merge_function_evidence,
)
from aether_re.engines.decompiler import merge_decompilation_results
from aether_re.engines.ghidra_parse import write_function_index
from aether_re.models import AnalysisReport, FunctionConsensus, FunctionEvidence


LIMITATIONS_BASE = [
    "Pseudo-fonte NÃO é o código-fonte original (nomes, comentários e estrutura de ficheiros perdem-se na compilação).",
    "Otimizações do compilador, inlining e stripping reduzem a precisão da reconstrução.",
    "Binários packed/cifrados exigem unpack dinâmico antes da análise estática profunda.",
    "Análise completa de caixa-preta combina estática + dinâmica + emulação + contexto humano.",
]


def _adapter_status(name: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "available": bool(result.get("available", result.get("executed", result.get("ok")))),
        "executed": bool(result.get("executed")),
        "ok": bool(result.get("ok", False)),
        "produced_evidence": bool(result.get("produced_evidence")),
        "partial": bool(result.get("partial")),
        "error": result.get("error"),
        "mode": result.get("mode"),
        "report": result.get("report"),
        "decompiled_path": result.get("decompiled_path"),
        "returncode": result.get("returncode"),
    }


def _record_adapter_failure(report: AnalysisReport, key: str, error: str) -> None:
    report.adapter_results[key] = {
        "ok": False,
        "available": False,
        "executed": False,
        "produced_evidence": False,
        "partial": False,
        "error": error,
    }


def _native_function_evidence(native: dict[str, Any]) -> list[FunctionEvidence]:
    items: list[FunctionEvidence] = []
    sketches = native.get("function_sketches", [])
    for index, sketch in enumerate(sketches, start=1):
        imports_used = list(getattr(sketch, "imports_used", []))
        evidence = FunctionEvidence(
            address=f"native:{index}",
            name=str(getattr(sketch, "name", f"cluster_{index}")),
            source="native",
            confidence=float(getattr(sketch, "confidence", 0.3)),
            quality=0.35,
            coverage=0.2,
            calls=[imp.split("!", 1)[-1] for imp in imports_used],
            imports_used=imports_used,
            strings_near=list(getattr(sketch, "strings_near", [])),
            notes=str(getattr(sketch, "notes", "")),
            warnings=["Cluster semântico sem endereço real da função."],
            raw={"role_cluster": True},
        )
        items.append(evidence)
    return items


def _render_function_md(function: FunctionConsensus) -> list[str]:
    lines = [
        "",
        f"### `{function.address}` — `{function.name}`",
        "",
        f"- **Fontes:** {', '.join(function.sources)}",
        f"- **Confiança:** {function.confidence:.2f}",
        f"- **Qualidade da evidência:** {function.evidence_quality:.2f}",
        f"- **Concordância:** {function.source_agreement:.2f}",
        f"- **Cobertura do ensemble:** {function.coverage:.2f}",
        f"- **Fonte selecionada:** `{function.selected_source}`",
    ]
    if function.aliases:
        lines.append(f"- **Aliases:** {', '.join(f'`{name}`' for name in function.aliases)}")
    if function.calls:
        lines.append(f"- **Chamadas observadas:** {', '.join(f'`{call}`' for call in function.calls[:30])}")
    if function.imports_used:
        lines.append(f"- **Imports associados:** {', '.join(f'`{imp}`' for imp in function.imports_used[:15])}")
    if function.warnings:
        lines.append(f"- **Avisos:** {'; '.join(function.warnings[:5])}")
    if function.pseudocode:
        lines += ["", "```c", function.pseudocode[:18000], "```"]
    elif function.disassembly:
        lines += ["", "```text", function.disassembly[:18000], "```"]
    return lines


def _render_md(report: AnalysisReport) -> str:
    lines = [
        "# AetherRE Megazord Report",
        "",
        f"- **Target:** `{report.target}`",
        f"- **SHA256:** `{report.target_sha256}`",
        f"- **Type:** {report.file_type}",
        f"- **Size:** {report.size_bytes} bytes",
        f"- **Entropy:** {report.entropy:.4f}",
        f"- **Overall confidence:** {report.overall_confidence:.2f}",
        f"- **Function coverage:** {report.coverage.get('ensemble', {}).get('mean', 0.0):.2f}",
        f"- **Engines:** {', '.join(report.engines_used)}",
        "",
        "## Trust and coverage",
        "",
        "```json",
        json.dumps(report.coverage, indent=2, ensure_ascii=False, default=str),
        "```",
        "",
        "## Limitations",
    ]
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    lines += ["", "## Findings"]
    for finding in report.findings:
        lines.append(
            f"- **[{finding.severity}/{finding.engine}]** {finding.title} "
            f"(conf={finding.confidence:.2f}): {finding.detail}"
        )
    lines += ["", "## Imports (top)"]
    lines.extend(f"- `{value}`" for value in report.imports[:50])
    lines += ["", "## Function consensus"]
    if report.merged_functions:
        for function in report.merged_functions:
            lines.extend(_render_function_md(function))
    else:
        lines.append("Nenhuma função endereçada foi produzida pelos adapters.")
    lines += [
        "",
        "## Adapter execution",
        "",
        "| Adapter | Available | Executed | Evidence | Partial | Status |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for name, result in report.adapter_results.items():
        if name.startswith("_"):
            continue
        lines.append(
            f"| {name} | {bool(result.get('available'))!s} | {bool(result.get('executed'))!s} | "
            f"{bool(result.get('produced_evidence'))!s} | {bool(result.get('partial'))!s} | "
            f"{('ok' if result.get('ok') else 'failed')} |"
        )
    lines += ["", "Pseudo-fonte completa: `pseudo_source.c`", "Índice por função: `ghidra_export/functions.json`"]
    return "\n".join(lines)


def adapters_status() -> list[dict[str, Any]]:
    return [
        GhidraAdapter().status(),
        RizinAdapter().status(),
        FridaAdapter().status(),
        UnicornAdapter().status(),
        AngrAdapter().status(),
        BinaryNinjaAdapter().status(),
    ]


def run_megazord(
    target: Path,
    out_dir: Path | None = None,
    use_adapters: bool = True,
    deep: bool = True,
) -> AnalysisReport:
    target = target.resolve()
    if not target.is_file():
        raise FileNotFoundError(target)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = (out_dir or Path("output") / f"{target.stem}_{stamp}").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report = AnalysisReport(target=str(target))
    report.limitations = list(LIMITATIONS_BASE)

    triage_result = triage.run_triage(target)
    report.target_sha256 = triage_result["sha256"]
    report.size_bytes = triage_result["size"]
    report.entropy = triage_result["entropy"]
    report.file_type = triage_result["file_type"]
    report.findings.extend(triage_result["findings"])
    report.engines_used.append("triage")
    raw: bytes = triage_result["raw"]

    structure = pe_elf.run_structure(raw)
    report.imports = structure.get("imports", [])
    report.exports = structure.get("exports", [])
    report.sections = structure.get("sections", [])
    report.findings.extend(structure.get("findings", []))
    report.engines_used.append("structure")
    is_64 = bool(structure.get("is_64", True))
    file_format = structure.get("format", report.file_type)
    entry = structure.get("entry_point", "")

    strings_result = strings_decode.run_strings_decode(raw)
    report.strings = strings_result.get("strings", [])
    report.decoded_payloads = strings_result.get("decoded_payloads", [])
    report.findings.extend(strings_result.get("findings", []))
    report.engines_used.append("strings_decode")

    if deep:
        disasm_result = disasm.run_disasm(raw, is_64=is_64, file_format=file_format)
        report.disassembly_snippets = disasm_result.get("snippets", [])
        report.findings.extend(disasm_result.get("findings", []))
        report.engines_used.append("disasm")

    reconstruct_result = reconstruct.run_reconstruct(
        target_name=target.name,
        file_format=file_format,
        entry_point=entry,
        imports=report.imports,
        exports=report.exports,
        sections=report.sections,
        strings=report.strings,
        decoded=report.decoded_payloads,
        disasm_snippets=report.disassembly_snippets,
    )
    report.function_sketches = reconstruct_result["function_sketches"]
    report.pseudo_source = reconstruct_result["pseudo_source"]
    report.findings.extend(reconstruct_result["findings"])
    report.engines_used.append("reconstruct")

    adapter_results: dict[str, dict[str, Any]] = {}
    if use_adapters:
        adapters: list[Any] = [GhidraAdapter(), RizinAdapter(), FridaAdapter(), UnicornAdapter(), AngrAdapter(), BinaryNinjaAdapter()]
        for adapter in adapters:
            key = adapter.name
            if adapter.available():
                try:
                    result = adapter.analyze(target, out_dir)
                    result["available"] = True
                    adapter_results[key] = result
                    report.engines_used.append(f"adapter:{key}")
                except Exception as exc:
                    adapter_results[key] = {
                        "ok": False,
                        "available": True,
                        "executed": True,
                        "produced_evidence": False,
                        "partial": False,
                        "error": str(exc),
                    }
            else:
                _record_adapter_failure(report, key, f"{key} não instalado ou indisponível")

    ghidra_result = adapter_results.get("ghidra", {})
    rizin_result = adapter_results.get("rizin", {})
    angr_result = adapter_results.get("angr", {})
    native_evidence = _native_function_evidence(reconstruct_result)
    successful_sources = [
        name for name, result in adapter_results.items() if result.get("produced_evidence")
    ]
    if angr_result.get("produced_evidence") and angr_result.get("functions"):
        successful_sources.append("angr")

    # Get base address for address normalization
    base_addr = 0
    if structure.get("image_base"):
        try:
            base_addr = int(structure["image_base"], 16) if isinstance(structure["image_base"], str) else structure["image_base"]
        except (ValueError, TypeError):
            pass

    evidence_items = [*native_evidence]
    if ghidra_result.get("decompiled_path") and Path(ghidra_result["decompiled_path"]).is_file():
        from aether_re.engines.ghidra_parse import parse_decompiled_file

        function_dicts = parse_decompiled_file(Path(ghidra_result["decompiled_path"]))
        evidence_items.extend(FunctionEvidence(**item) for item in function_dicts)
        write_function_index(function_dicts, out_dir / "ghidra_export" / "functions.json")
    if angr_result.get("functions"):
        evidence_items.extend(
            FunctionEvidence(**item) for item in angr_result["functions"]
        )
    if rizin_result.get("functions"):
        evidence_items.extend(
            FunctionEvidence(**item) for item in rizin_result["functions"]
        )

    merged_functions = merge_function_evidence(
        evidence_items,
        successful_sources=list(dict.fromkeys(successful_sources or ["native"])),
        base_addr=base_addr,
    )
    report.function_evidence = evidence_items
    report.merged_functions = merged_functions
    successful_sources = list(dict.fromkeys(successful_sources))
    if angr_result.get("produced_evidence"):
        successful_sources = list(dict.fromkeys([*successful_sources, "angr"]))
    failed_sources = [
        name for name, result in adapter_results.items() if not result.get("ok", False)
    ]
    report.overall_confidence, report.confidence_rationale = compute_overall_confidence(
        merged_functions,
        native_confidence=float(reconstruct_result.get("confidence", 0.5)),
        successful_sources=successful_sources,
        failed_sources=failed_sources,
    )
    report.coverage = {
        "ensemble": {
            "functions": len(merged_functions),
            "mean": sum(item.coverage for item in merged_functions) / len(merged_functions)
            if merged_functions
            else 0.0,
            "mean_confidence": sum(item.confidence for item in merged_functions) / len(merged_functions)
            if merged_functions
            else 0.0,
        },
        "sources": {
            name: {
                "available": bool(result.get("available")),
                "executed": bool(result.get("executed")),
                "produced_evidence": bool(result.get("produced_evidence")),
                "partial": bool(result.get("partial")),
            }
            for name, result in adapter_results.items()
        },
    }
    report.adapter_results = adapter_results
    report.adapter_results["_output_dir"] = str(out_dir)

    (out_dir / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    decompilation = merge_decompilation_results(
        ghidra_result if ghidra_result else None,
        rizin_result if rizin_result else None,
        reconstruct_result,
        angr_result if angr_result else None,
    )
    if decompilation.get("best_source") == "ghidra":
        ghidra_text = Path(ghidra_result["decompiled_path"]).read_text(
            encoding="utf-8", errors="replace"
        )
        report.pseudo_source = (
            "/* === GHIDRA DECOMPILATION (preferida) === */\n"
            + ghidra_text
            + "\n\n/* === MEGAZORD SEMANTIC SKELETON (context) === */\n"
            + report.pseudo_source
        )
    (out_dir / "pseudo_source.c").write_text(report.pseudo_source, encoding="utf-8")
    (out_dir / "findings.md").write_text(_render_md(report), encoding="utf-8")
    (out_dir / "strings.txt").write_text(
        "\n".join(report.strings), encoding="utf-8", errors="replace"
    )

    # Gerar relatórios comparativos
    comparative_dir = out_dir / "comparative"
    generate_comparative_report(report, comparative_dir)

    return report
