"""AetherRE Megazord — Universal Structural Binary Differ & Patch Analyzer.

Implementa algoritmos de comparação estrutural e heurística de funções inspirados
no Google BinDiff e Diaphora para engenharia reversa de 1-day patches, análise de
mutação de variantes de malware e verificação de integridade entre compilações.

Opera em conformidade com o rigor forense: fail-closed, determinístico e auditável.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from aether_re.engines import pe_elf, strings_decode, triage
from aether_re.function_simhash import (
    compute_function_simhash,
    extract_binary_simhashes,
    hamming_distance,
    simhash_similarity,
)
from aether_re.pipeline import run_megazord
from aether_re.semantic_labeler import infer_function_role

SCHEMA = "binary-diff-report.v1"


def _jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    if not set_a and not set_b:
        return 1.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


def _extract_binary_profile(target: Path, *, deep: bool = False) -> dict[str, Any]:
    raw = target.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    entropy = triage.shannon_entropy(raw[: 4 * 1024 * 1024])
    magic = triage.detect_magic(raw[:64])

    struct_info = pe_elf.run_structure(raw)
    ascii_s = strings_decode.extract_ascii_strings(raw, min_len=5)
    utf16_s = strings_decode.extract_utf16le_strings(raw, min_len=5)
    strings_set = set(ascii_s + utf16_s)

    imports = [str(x) for x in struct_info.get("imports", [])]
    exports = [str(x) for x in struct_info.get("exports", [])]
    sections = struct_info.get("sections", [])
    entry = struct_info.get("entry_point", "")
    arch = struct_info.get("arch", "unknown")

    # Funções de consenso quando deep=True ou fallback para exports/symbols
    functions: dict[str, dict[str, Any]] = {}

    if deep:
        try:
            report = run_megazord(target, deep=True)
            for fn in report.functions_consensus:
                name = fn.name or fn.address
                functions[name] = {
                    "address": fn.address,
                    "name": name,
                    "calls": fn.calls,
                    "imports_used": fn.imports_used,
                    "pseudocode_len": len(fn.pseudocode),
                    "disasm_len": len(fn.disassembly),
                    "confidence": fn.confidence,
                }
        except Exception:
            pass

    if not functions:
        # Heurística estática a partir de exports e símbolos observados
        for exp in exports:
            functions[exp] = {
                "address": "export",
                "name": exp,
                "calls": [],
                "imports_used": [],
                "pseudocode_len": 0,
                "disasm_len": 0,
                "confidence": 0.7,
            }
        for sym in struct_info.get("symbols", []):
            s_name = sym.get("name")
            if s_name and s_name not in functions:
                functions[s_name] = {
                    "address": hex(sym.get("value", 0)),
                    "name": s_name,
                    "calls": [],
                    "imports_used": [],
                    "pseudocode_len": 0,
                    "disasm_len": 0,
                    "confidence": 0.6,
                }

    return {
        "path": str(target.resolve()),
        "size_bytes": len(raw),
        "sha256": sha256,
        "format": magic,
        "arch": arch,
        "entry_point": entry,
        "entropy": round(entropy, 4),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "strings": strings_set,
        "functions": functions,
    }


def diff_binaries(
    target_a: Path,
    target_b: Path,
    *,
    deep: bool = False,
    max_string_diff: int = 50,
) -> dict[str, Any]:
    """Compara dois executáveis estruturalmente calculando deltas de código e funções."""
    p_a = Path(target_a)
    p_b = Path(target_b)

    if not p_a.is_file() or not p_b.is_file():
        return {
            "schema": SCHEMA,
            "status": "failed",
            "target_a": str(p_a),
            "target_b": str(p_b),
            "errors": [{"code": "target_file_not_found"}],
            "overall_similarity": 0.0,
            "limitations": ["um ou ambos os binários de entrada não existem ou são inacessíveis"],
        }

    # 1. Extração determinística de perfis
    prof_a = _extract_binary_profile(p_a, deep=deep)
    prof_b = _extract_binary_profile(p_b, deep=deep)

    # Identidade exata
    if prof_a["sha256"] == prof_b["sha256"]:
        return {
            "schema": SCHEMA,
            "status": "identical",
            "target_a": str(p_a.resolve()),
            "target_b": str(p_b.resolve()),
            "sha256": prof_a["sha256"],
            "overall_similarity": 1.0,
            "architecture_match": True,
            "imports_diff": {"added": [], "removed": [], "common_count": len(prof_a["imports"])},
            "exports_diff": {"added": [], "removed": [], "common_count": len(prof_a["exports"])},
            "sections_diff": {"added": [], "removed": [], "modified": []},
            "strings_diff": {"added_sample": [], "removed_sample": [], "jaccard_similarity": 1.0},
            "functions_diff": {
                "matched_identical": len(prof_a["functions"]),
                "matched_modified": 0,
                "added": 0,
                "removed": 0,
                "details": [],
            },
            "patch_analysis": {
                "is_patch_candidate": False,
                "significance": "none",
                "notes": ["binários possuem hashes criptográficos idênticos"],
            },
            "limitations": ["análise estática sem execução dinâmica dos alvos"],
        }

    arch_match = prof_a["format"] == prof_b["format"]

    # 2. Diffs de Imports e Exports
    set_imp_a = set(prof_a["imports"])
    set_imp_b = set(prof_b["imports"])
    added_imports = sorted(set_imp_b - set_imp_a)
    removed_imports = sorted(set_imp_a - set_imp_b)
    common_imports = set_imp_a & set_imp_b
    imp_sim = _jaccard_similarity(set_imp_a, set_imp_b)

    set_exp_a = set(prof_a["exports"])
    set_exp_b = set(prof_b["exports"])
    added_exports = sorted(set_exp_b - set_exp_a)
    removed_exports = sorted(set_exp_a - set_exp_b)

    # 3. Diffs de Strings Forenses
    str_a = prof_a["strings"]
    str_b = prof_b["strings"]
    added_strings = sorted(str_b - str_a)
    removed_strings = sorted(str_a - str_b)
    str_sim = _jaccard_similarity(str_a, str_b)

    # 4. Diffs de Seções
    sec_names_a = {s.get("name", ""): s for s in prof_a["sections"]}
    sec_names_b = {s.get("name", ""): s for s in prof_b["sections"]}

    added_sections = sorted(set(sec_names_b.keys()) - set(sec_names_a.keys()))
    removed_sections = sorted(set(sec_names_a.keys()) - set(sec_names_b.keys()))
    modified_sections = []

    for name in sorted(set(sec_names_a.keys()) & set(sec_names_b.keys())):
        s_a = sec_names_a[name]
        s_b = sec_names_b[name]
        size_diff = s_b.get("size", 0) - s_a.get("size", 0)
        ent_diff = s_b.get("entropy", 0.0) - s_a.get("entropy", 0.0)
        if abs(size_diff) > 0 or abs(ent_diff) > 0.05:
            modified_sections.append({
                "name": name,
                "size_delta_bytes": size_diff,
                "entropy_delta": round(ent_diff, 4),
            })

    # 5. Matching Heurístico de Funções (Estilo Diaphora / BinDiff)
    funcs_a = prof_a["functions"]
    funcs_b = prof_b["functions"]

    matched_identical = 0
    matched_modified = 0
    func_details: list[dict[str, Any]] = []

    all_fn_names = sorted(set(funcs_a.keys()) | set(funcs_b.keys()))
    added_funcs = [fn for fn in funcs_b if fn not in funcs_a]
    removed_funcs = [fn for fn in funcs_a if fn not in funcs_b]
    common_funcs = [fn for fn in funcs_a if fn in funcs_b]

    for fn_name in common_funcs:
        fa = funcs_a[fn_name]
        fb = funcs_b[fn_name]

        calls_a = set(fa.get("calls", []))
        calls_b = set(fb.get("calls", []))
        call_sim = _jaccard_similarity(calls_a, calls_b)

        ps_a_len = fa.get("pseudocode_len", 0)
        ps_b_len = fb.get("pseudocode_len", 0)
        len_diff = abs(ps_b_len - ps_a_len)

        role = infer_function_role(name=fn_name, calls=list(calls_a | calls_b))

        if call_sim == 1.0 and len_diff == 0:
            matched_identical += 1
            func_details.append({
                "name": fn_name,
                "status": "identical",
                "similarity": 1.0,
                "inferred_role": role["inferred_category"],
                "suggested_label": role["suggested_label"],
            })
        else:
            matched_modified += 1
            sim = round(0.5 * call_sim + 0.5 * (1.0 / (1.0 + len_diff / 50.0)), 4)
            func_details.append({
                "name": fn_name,
                "status": "modified",
                "similarity": sim,
                "inferred_role": role["inferred_category"],
                "suggested_label": role["suggested_label"],
                "added_calls": sorted(calls_b - calls_a),
                "removed_calls": sorted(calls_a - calls_b),
                "code_len_delta": ps_b_len - ps_a_len,
            })

    # 5.1 Extração e Pareamento via SimHash de 64 bits (Google Project Zero / SAFE style)
    simhash_matches: list[dict[str, Any]] = []
    try:
        simhashes_a = extract_binary_simhashes(p_a, is_64=prof_a.get("is_64", True))
        simhashes_b = extract_binary_simhashes(p_b, is_64=prof_b.get("is_64", True))
        for name_a, data_a in simhashes_a.items():
            sh_a = data_a.get("simhash", "")
            best_match_b = None
            best_sim = 0.0
            best_dist = 64
            for name_b, data_b in simhashes_b.items():
                sh_b = data_b.get("simhash", "")
                dist = hamming_distance(sh_a, sh_b)
                sim = simhash_similarity(sh_a, sh_b)
                if sim > best_sim:
                    best_sim = sim
                    best_dist = dist
                    best_match_b = name_b

            if best_match_b is not None:
                role_a = infer_function_role(name=name_a)
                role_b = infer_function_role(name=best_match_b)
                simhash_matches.append({
                    "function_a": name_a,
                    "function_b": best_match_b,
                    "simhash_a": sh_a,
                    "simhash_b": simhashes_b[best_match_b].get("simhash", ""),
                    "hamming_distance": best_dist,
                    "similarity": best_sim,
                    "inferred_role_a": role_a["inferred_category"],
                    "inferred_role_b": role_b["inferred_category"],
                })
    except Exception:
        pass

    # 6. Avaliação Geral de Similaridade e Potencial de Patch
    fn_total = len(all_fn_names) or 1
    fn_sim = (matched_identical * 1.0 + matched_modified * 0.7) / fn_total

    # Ponderação composta
    overall_sim = round(0.4 * fn_sim + 0.3 * imp_sim + 0.3 * str_sim, 4)

    is_patch = (
        0.50 <= overall_sim <= 0.99
        and (bool(matched_modified) or bool(added_imports) or bool(modified_sections))
    )

    significance = "none"
    if is_patch:
        if matched_modified > 5 or len(added_imports) > 3:
            significance = "high"
        elif matched_modified > 0 or added_imports:
            significance = "medium"
        else:
            significance = "low"

    notes = []
    if added_imports:
        notes.append(f"Novas APIs externas importadas no binário B ({len(added_imports)}): {added_imports[:5]}")
    if matched_modified:
        notes.append(f"{matched_modified} funções sofreram mutação de código ou alteração no grafo de chamadas.")
    if added_sections:
        notes.append(f"Novas seções incluídas: {added_sections}")

    return {
        "schema": SCHEMA,
        "status": "diff_completed",
        "target_a": str(p_a.resolve()),
        "target_b": str(p_b.resolve()),
        "target_a_sha256": prof_a["sha256"],
        "target_b_sha256": prof_b["sha256"],
        "architecture_match": arch_match,
        "overall_similarity": overall_sim,
        "imports_diff": {
            "added": added_imports,
            "removed": removed_imports,
            "common_count": len(common_imports),
            "similarity": round(imp_sim, 4),
        },
        "exports_diff": {
            "added": added_exports,
            "removed": removed_exports,
            "common_count": len(set_exp_a & set_exp_b),
        },
        "sections_diff": {
            "added": added_sections,
            "removed": removed_sections,
            "modified": modified_sections,
        },
        "strings_diff": {
            "added_sample": added_strings[:max_string_diff],
            "removed_sample": removed_strings[:max_string_diff],
            "jaccard_similarity": round(str_sim, 4),
        },
        "functions_diff": {
            "total_functions_a": len(funcs_a),
            "total_functions_b": len(funcs_b),
            "matched_identical": matched_identical,
            "matched_modified": matched_modified,
            "added": len(added_funcs),
            "removed": len(removed_funcs),
            "details": func_details[:50],
            "simhash_matches": simhash_matches[:50],
        },
        "patch_analysis": {
            "is_patch_candidate": is_patch,
            "significance": significance,
            "notes": notes,
        },
        "limitations": [
            "análise baseada em correlação de grafos e assinaturas estáticas; não garante equivalência semântica irrestrita",
            "heurística de matching de funções foca em chamadas e símbolos sem executar os alvos",
        ],
    }
