"""Structural diagnostics and a separately scoped C behavioral comparison.

A structural percentage is not decompilation fidelity or equivalence. Unknown
calls are never relabeled using the reference. Semantic claims require a
counterexample query over a supported explicit model, otherwise abstain.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from aether_re.c_equivalence import compare_c_functions


def _masked(text: str) -> str:
    tokens = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*'
    return re.sub(tokens, lambda m: "".join("\n" if c == "\n" else " " for c in m[0]), text, flags=re.S)


def _extract_c_function(source: str, name: str) -> str:
    mask = _masked(source)
    pattern = re.compile(
        r"(?:^|\n)[^\n;{}]*\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{"
    )
    match = pattern.search(mask)
    if match is None:
        return ""
    start_brace = mask.find("{", match.start())
    depth = 0
    for index in range(start_brace, len(mask)):
        if mask[index] == "{": depth += 1
        elif mask[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index+1].strip()
    return ""


def evaluate_decompilation_against_ground_truth(
    original_c_file: Path | str, decompiled_c_code: str, function_name: str,
) -> dict[str, Any]:
    original = Path(original_c_file).resolve()
    if not original.is_file():
        raise FileNotFoundError(f"Ground truth source not found: {original}")
    if not isinstance(function_name,str) or not re.fullmatch(r"[A-Za-z_]\w*",function_name):
        raise ValueError("invalid_function_name")
    if not isinstance(decompiled_c_code,str) or not decompiled_c_code.strip():
        raise ValueError("candidate_code_missing")
    if len(decompiled_c_code)>1024*1024 or original.stat().st_size>16*1024*1024:
        raise ValueError("source_budget_exceeded")
    source = original.read_text(encoding="utf-8",errors="strict")
    original_code = _extract_c_function(source,function_name)
    if not original_code:
        raise ValueError("reference_function_not_found")
    left, right = _masked(original_code), _masked(decompiled_c_code)
    excluded = {"if","while","for","switch","sizeof","return","do","code",function_name}
    # A function definition is not a call. No oracle-driven thunk/FUN/vtable
    # renaming is performed: unresolved correspondence remains unresolved.
    definitions = re.findall(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",right)
    pattern = re.compile(r"(?:\(\s*\*\s*([A-Za-z_]\w*)\s*\)|\b([A-Za-z_]\w*))\s*\(")
    original_calls = {m[1] or m[2] for m in pattern.finditer(left)} - excluded
    candidate_calls = {m[1] or m[2] for m in pattern.finditer(right)} - excluded - set(definitions)
    common_calls = original_calls & candidate_calls
    calls_rate = round(100*len(common_calls)/len(original_calls),2) if original_calls else None
    original_fields = set(re.findall(r"->([A-Za-z_]\w*)",left))
    candidate_fields = set(re.findall(r"->([A-Za-z_]\w*)",right))
    common_fields = original_fields & candidate_fields
    fields_rate = round(100*len(common_fields)/len(original_fields),2) if original_fields else None
    loop_matches = bool(re.search(r"\b(while|for|do)\b",left)) == bool(re.search(r"\b(while|for|do)\b",right))
    branch_matches = bool(re.search(r"\bif\b",left)) == bool(re.search(r"\bif\b",right))
    features = [100.0 if loop_matches else 0.0,100.0 if branch_matches else 0.0]
    features += [rate for rate in (calls_rate,fields_rate) if rate is not None]
    structural_score = round(sum(features)/len(features),2)
    return {
        "schema":"decompilation-comparison.v2",
        "function_name":function_name,
        "original_code_lines":len(original_code.splitlines()),
        "decompiled_code_lines":len(decompiled_c_code.splitlines()),
        "original_calls":sorted(original_calls), "decompiled_calls":sorted(candidate_calls),
        "preserved_calls":sorted(common_calls), "call_preservation_rate_pct":calls_rate,
        "original_fields":sorted(original_fields), "decompiled_fields":sorted(candidate_fields),
        "preserved_fields":sorted(common_fields), "field_preservation_rate_pct":fields_rate,
        "loop_structure_preserved":loop_matches, "branch_structure_preserved":branch_matches,
        "structural_similarity_score_pct":structural_score,
        "score_kind":"structural_features_only",
        "empirical_fidelity_score_pct":None,
        "behavioral_comparison":compare_c_functions(original_code,decompiled_c_code,function_name),
        "limitations":[
            "structural similarity does not measure semantic fidelity",
            "loop/branch flags compare presence, not control-flow equivalence",
            "unknown calls and virtual dispatch are not resolved from reference names",
            "behavioral comparison is scoped to its explicit model; unsupported memory/calls/control flow abstain",
            "decompiled pseudo-source is not original source",
        ],
    }
