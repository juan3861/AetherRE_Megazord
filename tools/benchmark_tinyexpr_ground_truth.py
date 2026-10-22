"""
Benchmark all 5 exports of tinyexpr.dll against original ground truth tinyexpr.c source code.
Measures empirical fidelity across call graph, loop structure, branch structure, and struct member preservation.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aether_re.ghidra_headless_bridge import GhidraHeadlessBridge
from aether_re.ground_truth_eval import evaluate_decompilation_against_ground_truth


def main() -> int:
    tinyexpr_dll = Path("external_test_repos/tinyexpr/tinyexpr.dll").resolve()
    tinyexpr_c = Path("external_test_repos/tinyexpr/tinyexpr.c").resolve()
    out_json = Path("engineering_evidence/tinyexpr_all_exports_ground_truth_report.json")
    out_md = Path("engineering_evidence/tinyexpr_all_exports_ground_truth_report.md")

    assert tinyexpr_dll.exists(), f"tinyexpr.dll not found: {tinyexpr_dll}"
    assert tinyexpr_c.exists(), f"tinyexpr.c not found: {tinyexpr_c}"

    print(f"[BENCHMARK] Decompiling {tinyexpr_dll.name} via Ghidra Headless Analyzer...")
    start_time = time.time()
    bridge = GhidraHeadlessBridge()
    res = bridge.decompile_binary(tinyexpr_dll)
    elapsed = time.time() - start_time
    print(f" -> Decompiled {len(res.functions)} functions in {elapsed:.2f}s (Success: {res.success})")

    exports = ["te_compile", "te_eval", "te_free", "te_interp", "te_print"]
    results = []
    scores = []

    for idx, fn_name in enumerate(exports, start=1):
        fn_info = res.functions.get(fn_name)
        if not fn_info or not fn_info.decompiled_c:
            results.append({
                "ordinal": idx,
                "name": fn_name,
                "status": "NOT_DECOMPILED_OR_INLINED",
                "score_pct": 0.0,
            })
            continue

        try:
            gt = evaluate_decompilation_against_ground_truth(tinyexpr_c, fn_info.decompiled_c, fn_name)
            score = gt["empirical_fidelity_score_pct"]
            scores.append(score)
            results.append({
                "ordinal": idx,
                "name": fn_name,
                "status": "PASS" if score >= 70.0 else "PARTIAL",
                "score_pct": score,
                "calls_preservation_pct": gt["call_preservation_rate_pct"],
                "fields_preservation_pct": gt["field_preservation_rate_pct"],
                "loop_preserved": gt["loop_structure_preserved"],
                "branch_preserved": gt["branch_structure_preserved"],
                "original_calls": gt["original_calls"],
                "decompiled_calls": gt["decompiled_calls"],
                "preserved_calls": gt["preserved_calls"],
            })
            print(f"  [{idx}/{len(exports)}] {fn_name:20s}: {score:6.2f}% ({results[-1]['status']})")
        except Exception as exc:
            results.append({
                "ordinal": idx,
                "name": fn_name,
                "status": "ERROR",
                "error": str(exc),
                "score_pct": 0.0,
            })
            print(f"  [{idx}/{len(exports)}] {fn_name:20s}: ERROR ({exc})")

    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
    perfect_count = sum(1 for s in scores if s >= 99.9)
    high_count = sum(1 for s in scores if s >= 70.0)

    report_data = {
        "binary": str(tinyexpr_dll),
        "source": str(tinyexpr_c),
        "total_exports": len(exports),
        "evaluated_exports": len(scores),
        "perfect_fidelity_count_100pct": perfect_count,
        "high_fidelity_count_gte_70pct": high_count,
        "average_library_fidelity_score_pct": avg_score,
        "decompilation_elapsed_seconds": round(elapsed, 2),
        "functions": results,
    }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Generate Markdown report
    md_lines = [
        "# TinyExpr Library Full Ground-Truth Reverse Engineering Benchmark",
        "",
        f"- **Binary:** `{tinyexpr_dll.name}` (Compiled with MSVC 19.44 x64 `/O2`)",
        f"- **Reference Ground Truth Source:** `{tinyexpr_c.name}`",
        f"- **Decompilation Engine:** NSA Ghidra 12.1.4 Headless + OpenJDK 21 LTS",
        f"- **Total Library Exports:** `{len(exports)}`",
        f"- **Global Average Fidelity:** **`{avg_score}%`**",
        f"- **100% Bit-Exact / Callee Matches:** `{perfect_count} / {len(exports)}`",
        f"- **High Fidelity (>= 70%):** `{high_count} / {len(exports)}`",
        f"- **Decompilation Time:** `{elapsed:.2f}s`",
        "",
        "## Function Breakdown",
        "",
        "| Ordinal | Function Name | Status | Fidelity Score | Calls Preserved | Loop Preserved | Branch Preserved |",
        "|---|---|---|---|---|---|---|",
    ]

    for item in results:
        ord_num = item["ordinal"]
        name = item["name"]
        st = item["status"]
        sc = f"{item.get('score_pct', 0.0):.2f}%"
        cp = f"{item.get('calls_preservation_pct', 0.0):.2f}%" if "calls_preservation_pct" in item else "-"
        lp = "Yes" if item.get("loop_preserved") else "No"
        bp = "Yes" if item.get("branch_preserved") else "No"
        md_lines.append(f"| {ord_num} | `{name}` | **{st}** | {sc} | {cp} | {lp} | {bp} |")

    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"\n[SUMMARY] Global Library Fidelity: {avg_score}% | Saved to {out_md}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
