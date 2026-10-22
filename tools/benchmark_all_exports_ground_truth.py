"""
AetherRE SOTA All-Exports Ground Truth Benchmark
================================================
Systematically evaluates decompiler ground truth fidelity across all 78 exported
functions of cjson.dll against the original cJSON.c source code.
Measures:
  - Callee preservation rate
  - Field access preservation rate (struct members)
  - Control flow preservation (loops and branches)
  - Composite mathematical fidelity score
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pefile
from aether_re.ghidra_headless_bridge import GhidraHeadlessBridge
from aether_re.ground_truth_eval import evaluate_decompilation_against_ground_truth


def main():
    print("================================================================================")
    print("AETHER-RE ALL-EXPORTS GROUND TRUTH BENCHMARK")
    print("Evaluating all exported functions of cjson.dll against cJSON.c source code")
    print("================================================================================")

    target_dll = PROJECT_ROOT / "external_test_repos" / "cjson" / "cjson.dll"
    source_c = PROJECT_ROOT / "external_test_repos" / "cjson" / "cJSON.c"

    assert target_dll.exists(), f"Target DLL missing: {target_dll}"
    assert source_c.exists(), f"Source C missing: {source_c}"

    # 1. Read all exports
    pe = pefile.PE(str(target_dll))
    export_names = [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name]
    print(f"Total exported functions discovered: {len(export_names)}")

    # 2. Run Ghidra with struct type injection
    cache_dir = PROJECT_ROOT / "engineering_evidence" / "ghidra_typed_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    bridge = GhidraHeadlessBridge()
    t0 = time.time()
    res = bridge.decompile_binary(
        target_dll,
        timeout_seconds=300,
        temp_work_dir=cache_dir,
        max_cpu=4,
        script_name="DecompileWithTypeInjection.java",
    )
    elapsed = time.time() - t0
    print(f"Ghidra decompilation completed in {elapsed:.2f}s (Success: {res.success})")
    assert res.success, f"Ghidra execution failed: {res.error_message}"

    # 3. Evaluate each export against ground truth
    results = []
    scores = []

    for idx, fn_name in enumerate(export_names, start=1):
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
            gt = evaluate_decompilation_against_ground_truth(source_c, fn_info.decompiled_c, fn_name)
            score = gt["empirical_fidelity_score_pct"]
            scores.append(score)

            results.append({
                "ordinal": idx,
                "name": fn_name,
                "status": "PASS",
                "score_pct": score,
                "calls_preservation_pct": gt["call_preservation_rate_pct"],
                "fields_preservation_pct": gt["field_preservation_rate_pct"],
                "loop_preserved": gt["loop_structure_preserved"],
                "branch_preserved": gt["branch_structure_preserved"],
                "orig_lines": gt["original_code_lines"],
                "dec_lines": gt["decompiled_code_lines"],
                "preserved_fields": gt["preserved_fields"],
                "preserved_calls": gt["preserved_calls"],
            })
        except Exception as ex:
            results.append({
                "ordinal": idx,
                "name": fn_name,
                "status": f"EVAL_ERROR: {str(ex)}",
                "score_pct": 0.0,
            })

    # 4. Compute distribution
    total_evaluated = len(results)
    successful = [r for r in results if r["status"] == "PASS"]
    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
    above_80 = len([s for s in scores if s >= 80.0])
    above_70 = len([s for s in scores if s >= 70.0])
    perfect_100 = len([s for s in scores if s == 100.0])

    print("\n--------------------------------------------------------------------------------")
    print(f"Total Exports: {total_evaluated}")
    print(f"Successfully Evaluated: {len(successful)}/{total_evaluated} ({len(successful)/total_evaluated*100:.1f}%)")
    print(f"Average Ground Truth Fidelity: {avg_score}%")
    print(f"Perfect 100% Fidelity Functions: {perfect_100}")
    print(f"Functions with >=80% Fidelity: {above_80} ({above_80/len(scores)*100:.1f}%)")
    print(f"Functions with >=70% Fidelity: {above_70} ({above_70/len(scores)*100:.1f}%)")
    print("--------------------------------------------------------------------------------")

    # 5. Save Artifacts
    report_data = {
        "benchmark_name": "cjson_all_exports_ground_truth",
        "total_exports": total_evaluated,
        "successfully_evaluated": len(successful),
        "average_fidelity_pct": avg_score,
        "perfect_100_count": perfect_100,
        "above_80_count": above_80,
        "above_70_count": above_70,
        "functions": results,
    }

    out_json = PROJECT_ROOT / "engineering_evidence" / "cjson_all_exports_ground_truth_report.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Generate Markdown Table
    out_md = PROJECT_ROOT / "engineering_evidence" / "cjson_all_exports_ground_truth_report.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# cJSON.dll 78 Exported Functions — Ground Truth Fidelity Benchmark\n\n")
        f.write(f"- **Total Exported Functions:** {total_evaluated}\n")
        f.write(f"- **Average Empirical Fidelity:** {avg_score}%\n")
        f.write(f"- **Functions >= 80% Fidelity:** {above_80} ({above_80/len(scores)*100:.1f}%)\n")
        f.write(f"- **Functions == 100% Fidelity:** {perfect_100}\n\n")
        f.write("| # | Function Name | Status | Fidelity Score | Calls Preserved | Fields Preserved | Loop | Branch |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")
        for r in results:
            if r["status"] == "PASS":
                f.write(f"| {r['ordinal']} | `{r['name']}` | {r['status']} | **{r['score_pct']}%** | {r['calls_preservation_pct']}% | {r['fields_preservation_pct']}% | {'✓' if r['loop_preserved'] else '✗'} | {'✓' if r['branch_preserved'] else '✗'} |\n")
            else:
                f.write(f"| {r['ordinal']} | `{r['name']}` | {r['status']} | 0.0% | - | - | - | - |\n")

    print(f"\n[EVIDENCE SAVED]:")
    print(f"  JSON: {out_json}")
    print(f"  Markdown Table: {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
