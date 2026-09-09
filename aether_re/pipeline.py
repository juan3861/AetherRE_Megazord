"""Pipeline principal do Megazord — funde todos os motores + adapters."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aether_re.engines import disasm, pe_elf, reconstruct, strings_decode, triage
from aether_re.engines.consensus import compute_overall_confidence
from aether_re.models import AnalysisReport
from aether_re.adapters.ghidra import GhidraAdapter
from aether_re.adapters.rizin import RizinAdapter
from aether_re.adapters.frida_dyn import FridaAdapter
from aether_re.adapters.unicorn_emu import UnicornAdapter
from aether_re.adapters.angr import AngrAdapter


LIMITATIONS_BASE = [
    "Pseudo-fonte NÃO é o código-fonte original (nomes, comentários e estrutura de ficheiros perdem-se na compilação).",
    "Otimizações do compilador, inlining e stripping reduzem a precisão da reconstrução.",
    "Binários packed/cifrados exigem unpack dinâmico antes da análise estática profunda.",
    "Análise completa de caixa-preta combina estática + dinâmica + emulação + contexto humano.",
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

    # 1) TRIAGE
    t = triage.run_triage(target)
    report.target_sha256 = t["sha256"]
    report.size_bytes = t["size"]
    report.entropy = t["entropy"]
    report.file_type = t["file_type"]
    report.findings.extend(t["findings"])
    report.engines_used.append("triage")
    raw: bytes = t["raw"]

    # 2) STRUCTURE (PE/ELF)
    st = pe_elf.run_structure(raw)
    report.imports = st.get("imports", [])
    report.exports = st.get("exports", [])
    report.sections = st.get("sections", [])
    report.findings.extend(st.get("findings", []))
    report.engines_used.append("structure")
    is_64 = bool(st.get("is_64", True))
    file_format = st.get("format", report.file_type)
    entry = st.get("entry_point", "")

    # 3) STRINGS + DECODE
    sd = strings_decode.run_strings_decode(raw)
    report.strings = sd.get("strings", [])
    report.decoded_payloads = sd.get("decoded_payloads", [])
    report.findings.extend(sd.get("findings", []))
    report.engines_used.append("strings_decode")

    # 4) DISASM
    if deep:
        ds = disasm.run_disasm(raw, is_64=is_64, file_format=file_format)
        report.disassembly_snippets = ds.get("snippets", [])
        report.findings.extend(ds.get("findings", []))
        report.engines_used.append("disasm")

    # 5) RECONSTRUCT pseudo-source
    rc = reconstruct.run_reconstruct(
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
    report.function_sketches = rc["function_sketches"]
    report.pseudo_source = rc["pseudo_source"]
    report.findings.extend(rc["findings"])
    report.engines_used.append("reconstruct")

    # 6) ADAPTERS (best-effort)
    if use_adapters:
        adapters = [
            GhidraAdapter(),
            RizinAdapter(),
            FridaAdapter(),
            UnicornAdapter(),
        ]
        for ad in adapters:
            key = ad.name
            if ad.available():
                try:
                    report.adapter_results[key] = ad.analyze(target, out_dir)
                    report.engines_used.append(f"adapter:{key}")
                except Exception as e:
                    report.adapter_results[key] = {"ok": False, "error": str(e)}
            else:
                report.adapter_results[key] = {
                    "ok": False,
                    "available": False,
                    "error": f"{key} não instalado",
                }

        # se Ghidra devolveu decompilação, anexar
        gh = report.adapter_results.get("ghidra") or {}
        dep = gh.get("decompiled_path")
        if dep and Path(dep).is_file():
            decomp = Path(dep).read_text(encoding="utf-8", errors="replace")
            report.pseudo_source = (
                "/* === GHIDRA DECOMPILATION (preferida) === */\n"
                + decomp
                + "\n\n/* === MEGAZORD SEMANTIC SKELETON (fallback/context) === */\n"
                + report.pseudo_source
            )
            report.overall_confidence = max(report.overall_confidence, 0.75)

    # confiança global via CONSENSUS ENGINE
    ghidra_ok = report.adapter_results.get("ghidra", {}).get("ok", False)
    rizin_ok = report.adapter_results.get("rizin", {}).get("ok", False)
    angr_ok = report.adapter_results.get("angr", {}).get("ok", False)
    native_conf = rc.get("confidence", 0.5)

    report.overall_confidence = compute_overall_confidence(
        ghidra_available=ghidra_ok,
        rizin_available=rizin_ok,
        capstone_available=True,
        native_confidence=native_conf,
    )

    # persist
    (out_dir / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    (out_dir / "pseudo_source.c").write_text(report.pseudo_source, encoding="utf-8")
    (out_dir / "findings.md").write_text(_render_md(report), encoding="utf-8")
    (out_dir / "strings.txt").write_text(
        "\n".join(report.strings), encoding="utf-8", errors="replace"
    )

    report.adapter_results["_output_dir"] = str(out_dir)
    return report


def _render_md(r: AnalysisReport) -> str:
    lines = [
        f"# AetherRE Megazord Report",
        "",
        f"- **Target:** `{r.target}`",
        f"- **SHA256:** `{r.target_sha256}`",
        f"- **Type:** {r.file_type}",
        f"- **Size:** {r.size_bytes} bytes",
        f"- **Entropy:** {r.entropy:.4f}",
        f"- **Overall confidence:** {r.overall_confidence:.2f}",
        f"- **Engines:** {', '.join(r.engines_used)}",
        "",
        "## Limitações",
    ]
    for lim in r.limitations:
        lines.append(f"- {lim}")
    lines += ["", "## Findings"]
    for f in r.findings:
        lines.append(
            f"- **[{f.severity}/{f.engine}]** {f.title} "
            f"(conf={f.confidence:.2f}): {f.detail}"
        )
    lines += ["", "## Imports (top)", ""]
    for i in r.imports[:50]:
        lines.append(f"- `{i}`")
    lines += ["", "## Function sketches", ""]
    for sk in r.function_sketches:
        lines.append(f"### `{sk.name}` (conf={sk.confidence:.2f})")
        lines.append(f"- {sk.notes}")
        if sk.imports_used:
            lines.append("- imports: " + ", ".join(f"`{x}`" for x in sk.imports_used[:10]))
        lines.append("")
    lines += [
        "",
        "## Adapters",
        "```json",
        json.dumps(
            {k: v for k, v in r.adapter_results.items() if not k.startswith("_")},
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        "```",
        "",
        "Pseudo-fonte completa: `pseudo_source.c`",
    ]
    return "\n".join(lines)


def adapters_status() -> list[dict[str, Any]]:
    return [
        GhidraAdapter().status(),
        RizinAdapter().status(),
        FridaAdapter().status(),
        UnicornAdapter().status(),
        AngrAdapter().status(),
    ]
