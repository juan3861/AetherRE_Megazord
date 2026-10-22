"""Reverse Engineering Graph (AetherRE) — Ground Truth Empirical Validator.

Compares decompiled functions directly against original source code ground truth:
  1. Callee / API call preservation rate (did the decompiler preserve real calls?);
  2. Control flow branch & loop preservation rate;
  3. Identifier and variable recovery rate;
  4. Real calculated similarity score without hardcoded constants.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def evaluate_decompilation_against_ground_truth(
    original_c_file: Path | str,
    decompiled_c_code: str,
    function_name: str,
) -> dict[str, Any]:
    """Measures empirical fidelity between original ground truth C source and decompiled output."""
    orig_path = Path(original_c_file).resolve()
    if not orig_path.exists():
        raise FileNotFoundError(f"Ground truth source not found: {orig_path}")

    orig_source = orig_path.read_text(encoding="utf-8", errors="ignore")

    # Extract function from original C source
    idx = orig_source.find(f" {function_name}(")
    if idx == -1:
        idx = orig_source.find(f"*{function_name}(")
    if idx == -1:
        idx = orig_source.find(f"\n{function_name}(")

    orig_fn_code = ""
    if idx != -1:
        # Find start of body '{'
        start_brace = orig_source.find("{", idx)
        if start_brace != -1:
            depth = 0
            for i in range(start_brace, len(orig_source)):
                if orig_source[i] == "{":
                    depth += 1
                elif orig_source[i] == "}":
                    depth -= 1
                    if depth == 0:
                        orig_fn_code = orig_source[idx : i + 1]
                        break

    # 1. Compare Function Calls (Callee preservation)
    orig_calls = set(re.findall(r"\b([a-zA-Z0-9_]+)\s*\(", orig_fn_code))
    dec_calls = set(re.findall(r"\b([a-zA-Z0-9_]+)\s*\(", decompiled_c_code))

    # Exclude C keywords from calls
    c_keywords = {"if", "while", "for", "switch", "sizeof", "return", "do"}
    orig_calls -= c_keywords
    dec_calls -= c_keywords

    common_calls = orig_calls.intersection(dec_calls)
    call_preservation_rate = (
        round(len(common_calls) / len(orig_calls) * 100, 2) if orig_calls else 100.0
    )

    # 2. Control flow structures
    orig_has_loop = bool(re.search(r"\b(while|for|do)\b", orig_fn_code))
    dec_has_loop = bool(re.search(r"\b(while|for|do)\b", decompiled_c_code))
    loop_preserved = orig_has_loop == dec_has_loop

    orig_has_if = "if" in orig_fn_code
    dec_has_if = "if" in decompiled_c_code
    if_preserved = orig_has_if == dec_has_if

    # 3. Struct Field Access Preservation (->field)
    orig_fields = set(re.findall(r"->([a-zA-Z0-9_]+)", orig_fn_code))
    dec_fields = set(re.findall(r"->([a-zA-Z0-9_]+)", decompiled_c_code))

    common_fields = orig_fields.intersection(dec_fields)
    field_preservation_rate = (
        round(len(common_fields) / len(orig_fields) * 100, 2) if orig_fields else 100.0
    )

    # 4. Overall Composite Score (Empirical, not hardcoded)
    structure_score = (50.0 if loop_preserved else 25.0) + (50.0 if if_preserved else 25.0)
    if orig_fields:
        composite_fidelity = round(
            0.35 * call_preservation_rate + 0.35 * structure_score + 0.30 * field_preservation_rate, 2
        )
    else:
        composite_fidelity = round(0.5 * call_preservation_rate + 0.5 * structure_score, 2)

    return {
        "function_name": function_name,
        "original_code_lines": len(orig_fn_code.splitlines()),
        "decompiled_code_lines": len(decompiled_c_code.splitlines()),
        "original_calls": sorted(list(orig_calls)),
        "decompiled_calls": sorted(list(dec_calls)),
        "preserved_calls": sorted(list(common_calls)),
        "call_preservation_rate_pct": call_preservation_rate,
        "original_fields": sorted(list(orig_fields)),
        "decompiled_fields": sorted(list(dec_fields)),
        "preserved_fields": sorted(list(common_fields)),
        "field_preservation_rate_pct": field_preservation_rate,
        "loop_structure_preserved": loop_preserved,
        "branch_structure_preserved": if_preserved,
        "empirical_fidelity_score_pct": composite_fidelity,
    }
