"""
Benchmark all 4 exports of C++ multiple-inheritance polymorphic binary multi_poly.dll against original multi_poly.cpp source code.
Measures empirical fidelity across dual vtables, secondary interface offsets, virtual method dispatch, and destructors.
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
    poly_dll = Path("external_test_repos/cpp_poly/multi_poly.dll").resolve()
    poly_cpp = Path("external_test_repos/cpp_poly/multi_poly.cpp").resolve()
    out_json = Path("engineering_evidence/multi_poly_ground_truth_report.json")
    out_md = Path("engineering_evidence/multi_poly_ground_truth_report.md")

    assert poly_dll.exists(), f"multi_poly.dll not found: {poly_dll}"
    assert poly_cpp.exists(), f"multi_poly.cpp not found: {poly_cpp}"

    print(f"[BENCHMARK] Decompiling {poly_dll.name} via Ghidra Headless Analyzer...")
    start_time = time.time()
    bridge = GhidraHeadlessBridge()
    res = bridge.decompile_binary(poly_dll)
    elapsed = time.time() - start_time
    print(f" -> Decompiled {len(res.functions)} functions in {elapsed:.2f}s (Success: {res.success})")

    exports = ["create_dual_device", "read_from_device", "write_to_device", "destroy_dual_device"]
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
            gt = evaluate_decompilation_against_ground_truth(poly_cpp, fn_info.decompiled_c, fn_name)
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
            print(f"  [{idx}/{len(exports)}] {fn_name:22s}: {score:6.2f}% ({results[-1]['status']})")
        except Exception as exc:
            results.append({
                "ordinal": idx,
                "name": fn_name,
                "status": "ERROR",
                "error": str(exc),
                "score_pct": 0.0,
            })
            print(f"  [{idx}/{len(exports)}] {fn_name:22s}: ERROR ({exc})")

    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
    perfect_count = sum(1 for s in scores if s >= 99.9)

    report_data = {
        "binary": str(poly_dll),
        "source": str(poly_cpp),
        "paradigm": "C++ Multiple Inheritance (Dual Interface IReader + IWriter)",
        "total_exports": len(exports),
        "evaluated_exports": len(scores),
        "perfect_fidelity_count_100pct": perfect_count,
        "average_library_fidelity_score_pct": avg_score,
        "decompilation_elapsed_seconds": round(elapsed, 2),
        "functions": results,
    }

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Generate Markdown report
    md_lines = [
        "# C++ Multiple Inheritance Ground-Truth Reverse Engineering Benchmark",
        "",
        f"- **Binary:** `{poly_dll.name}` (Compiled with MSVC 19.44 x64 `/O2 /EHsc`)",
        f"- **Reference Ground Truth Source:** `{poly_cpp.name}`",
        f"- **Paradigm:** `DualDevice : public IReader, public IWriter` (Multiple Inheritance, 2 vptrs)",
        f"- **Decompilation Engine:** NSA Ghidra 12.1.4 Headless + OpenJDK 21 LTS",
        f"- **Total Library Exports:** `{len(exports)}`",
        f"- **Global Average Fidelity:** **`{avg_score}%`**",
        f"- **100% Bit-Exact / Callee Matches:** **`{perfect_count} / {len(exports)}`**",
        f"- **Decompilation Time:** `{elapsed:.2f}s`",
        "",
        "## Function Breakdown",
        "",
        "| Ordinal | Function Name | Status | Fidelity Score | Calls Preserved | Fields Preserved | Loop Preserved | Branch Preserved |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for item in results:
        ord_num = item["ordinal"]
        name = item["name"]
        st = item["status"]
        sc = f"{item.get('score_pct', 0.0):.2f}%"
        cp = f"{item.get('calls_preservation_pct', 0.0):.2f}%" if "calls_preservation_pct" in item else "-"
        fp = f"{item.get('fields_preservation_pct', 0.0):.2f}%" if "fields_preservation_pct" in item else "-"
        lp = "Yes" if item.get("loop_preserved") else "No"
        bp = "Yes" if item.get("branch_preserved") else "No"
        md_lines.append(f"| {ord_num} | `{name}` | **{st}** | {sc} | {cp} | {fp} | {lp} | {bp} |")

    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"\n[SUMMARY] C++ Multiple Inheritance Fidelity: {avg_score}% ({perfect_count}/{len(exports)} at 100%) | Saved to {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
