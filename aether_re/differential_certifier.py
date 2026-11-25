"""Closed-Loop CEGIS Differential Equivalence Certifier (v16.0).

Executes live black-box differential testing between an original native DLL
and its reconstructed compiled twin (`reconstructed_twin.dll`) over boundary,
angr-seeded, and stress input vectors.

If any divergence is detected, performs Counterexample-Guided Inductive Synthesis
(CEGIS) auto-repair on the reconstructed C source (fixing 32/64-bit sign/zero
extension widths or constant linear bias), cleanly releases the Windows DLL
handle via `FreeLibrary`, recompiles via MSVC/clang, and re-verifies 100.0% parity.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
from pathlib import Path
import random
import re
from typing import Any, Sequence

from aether_re.runtime_emitter import compile_reconstructed_project


def _unload_cdll(lib: Any) -> None:
    """Release loaded native DLL handle so Windows allows subsequent recompilation."""
    handle = getattr(lib, "_handle", None)
    del lib
    if handle is None:
        return
    try:
        import _ctypes  # type: ignore

        if hasattr(_ctypes, "FreeLibrary"):
            _ctypes.FreeLibrary(handle)
        elif hasattr(_ctypes, "dlclose"):
            _ctypes.dlclose(handle)
    except Exception:
        pass


def _build_stress_vectors(num_random: int = 200, seed: int = 2026) -> list[tuple[int, int, int, int]]:
    base: list[tuple[int, int, int, int]] = [
        (0, 0, 0, 0),
        (1, 2, 3, 4),
        (-1, -1, 0, 0),
        (42, 13, 7, 5),
        (-500, 250, 10, 20),
        (0x7FFFFFFF, 1, 0, 0),
        (-0x80000000, 0, 0, 0),
        (0x80000005, 3, 0, 0),
    ]
    rng = random.Random(seed)
    for _ in range(num_random):
        base.append(
            (
                rng.randint(-1_000_000_000, 2_500_000_000),
                rng.randint(-1_000_000, 1_000_000),
                rng.randint(-10_000, 10_000),
                rng.randint(0, 1000),
            )
        )
    return base


def _eval_dll_pairs(
    orig_dll: Path,
    twin_dll: Path,
    fn_names: Sequence[str],
    vectors: Sequence[tuple[int, int, int, int]],
) -> tuple[int, list[dict[str, Any]]]:
    lib_orig = ctypes.CDLL(str(orig_dll.resolve()))
    lib_twin = ctypes.CDLL(str(twin_dll.resolve()))
    divergences: list[dict[str, Any]] = []
    total_execs = 0
    try:
        for fn in fn_names:
            f_o = getattr(lib_orig, fn)
            f_t = getattr(lib_twin, fn)
            f_o.argtypes = [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64]
            f_t.argtypes = [ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64]
            f_o.restype = ctypes.c_int64
            f_t.restype = ctypes.c_int64
            for vec in vectors:
                total_execs += 1
                vo = int(f_o(vec[0], vec[1], vec[2], vec[3]))
                vt = int(f_t(vec[0], vec[1], vec[2], vec[3]))
                if vo != vt:
                    divergences.append(
                        {
                            "function": fn,
                            "vector": list(vec),
                            "orig": vo,
                            "twin": vt,
                        }
                    )
    finally:
        _unload_cdll(lib_orig)
        _unload_cdll(lib_twin)
    return total_execs, divergences


def _find_c_function_span(src: str, fn: str) -> tuple[int, int, int] | None:
    """Locate (fn_start, body_open_brace_idx, body_close_brace_idx) for `fn` regardless of indentation."""
    m = re.search(rf"\b{re.escape(fn)}\s*\([^)]*\)\s*\{{", src)
    if not m:
        return None
    open_idx = m.end() - 1
    depth = 0
    for i in range(open_idx, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return m.start(), open_idx, i
    return None


def _attempt_cegis_repair(
    twin_c_path: Path,
    divergences_by_fn: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Synthesize minimal semantic width/bias patches in C twin source from counterexamples."""
    src = twin_c_path.read_text(encoding="utf-8", errors="replace")
    repairs: list[dict[str, Any]] = []

    for fn, divs in divergences_by_fn.items():
        span = _find_c_function_span(src, fn)
        if not span:
            continue
        _, open_idx, close_idx = span
        body = src[open_idx + 1 : close_idx]
        low32_match = all((d["orig"] & 0xFFFFFFFF) == (d["twin"] & 0xFFFFFFFF) for d in divs)
        new_body = body

        if low32_match:
            # Determine whether orig zero-extends or sign-extends 32-bit return
            zero_ext_needed = any((d["orig"] >= 0 and (d["orig"] & 0x80000000) and d["twin"] < 0) for d in divs)
            sign_ext_needed = any((d["orig"] < 0 and d["twin"] >= 0) for d in divs)
            ret_pat = re.compile(r"(return\s+)([^;]+)(;)")
            if zero_ext_needed:
                new_body = ret_pat.sub(r"\1(int64_t)(uint32_t)(\2)\3", body)
                kind = "cegis_width_zero_extend_u32"
            elif sign_ext_needed:
                new_body = ret_pat.sub(r"\1(int64_t)(int32_t)(\2)\3", body)
                kind = "cegis_width_sign_extend_i32"
            else:
                continue
        else:
            deltas = {d["orig"] - d["twin"] for d in divs}
            if len(deltas) != 1:
                continue
            delta = next(iter(deltas))
            ret_pat = re.compile(r"(return\s+)([^;]+)(;)")
            new_body = ret_pat.sub(rf"\1((\2) + ({delta}LL))\3", body)
            kind = f"cegis_constant_bias_{delta}"

        if new_body != body:
            src = src[: open_idx + 1] + new_body + src[close_idx:]
            repairs.append({"function": fn, "strategy": kind, "counterexamples_used": len(divs)})

    if repairs:
        twin_c_path.write_text(src, encoding="utf-8")
    return repairs


def certify_differential_parity(
    orig_dll_path: str | Path,
    twin_project_dir: str | Path,
    function_names: Sequence[str],
    *,
    twin_dll_name: str = "reconstructed_twin.dll",
    source_rel: str = "src/reconstructed_project.c",
    vectors: Sequence[tuple[int, int, int, int]] | None = None,
    auto_repair: bool = True,
    max_repair_rounds: int = 3,
    output_cert_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run black-box differential parity fuzzing with optional closed-loop CEGIS auto-repair."""
    orig_p = Path(orig_dll_path).resolve()
    proj_p = Path(twin_project_dir).resolve()
    twin_p = proj_p / twin_dll_name
    twin_c = proj_p / source_rel
    if not orig_p.is_file() or not twin_p.is_file():
        raise FileNotFoundError(f"Both DLLs must exist: orig={orig_p}, twin={twin_p}")

    test_vecs = list(vectors or _build_stress_vectors())
    total_execs, initial_divs = _eval_dll_pairs(orig_p, twin_p, function_names, test_vecs)
    current_divs = initial_divs
    repairs_history: list[dict[str, Any]] = []

    round_idx = 0
    while auto_repair and current_divs and round_idx < max_repair_rounds and twin_c.is_file():
        round_idx += 1
        by_fn: dict[str, list[dict[str, Any]]] = {}
        for d in current_divs:
            by_fn.setdefault(d["function"], []).append(d)
        applied = _attempt_cegis_repair(twin_c, by_fn)
        if not applied:
            break
        comp = compile_reconstructed_project(proj_p, output_dll_name=twin_dll_name, source_rel=source_rel)
        if not comp.get("compiled"):
            break
        repairs_history.extend(applied)
        total_execs, current_divs = _eval_dll_pairs(orig_p, twin_p, function_names, test_vecs)

    passed = max(0, total_execs - len(current_divs))
    parity_pct = round((passed / total_execs) * 100.0, 4) if total_execs else 0.0

    cert = {
        "schema": "differential-parity.v1",
        "orig_dll": str(orig_p),
        "orig_sha256": hashlib.sha256(orig_p.read_bytes()).hexdigest(),
        "twin_dll": str(twin_p),
        "twin_sha256": hashlib.sha256(twin_p.read_bytes()).hexdigest(),
        "functions_tested": list(function_names),
        "vectors_per_function": len(test_vecs),
        "total_executions": total_execs,
        "divergences_before_repair": len(initial_divs),
        "divergences_after_repair": len(current_divs),
        "differential_parity_pct": parity_pct,
        "certified_100pct": len(current_divs) == 0 and total_execs > 0,
        "cegis_repairs_applied": repairs_history,
        "remaining_divergences_sample": current_divs[:8],
    }
    if output_cert_path is not None:
        cp = Path(output_cert_path)
        cp.parent.mkdir(parents=True, exist_ok=True)
        cp.write_text(json.dumps(cert, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        cert["certificate_path"] = str(cp)
    return cert
