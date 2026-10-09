"""Comparação comportamental de observações já coletadas (sem executar alvos)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Iterator


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _counterexample_identity(value: Any) -> dict[str, str]:
    """Return a deterministic identity for replay/reduction of one input.

    The digest covers the exact canonical JSON representation used by the
    comparator.  It is an identity handle, not a proof that the input is
    unique outside this report or that a future environment will execute it
    identically.
    """
    canonical = _canonical(value)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {"input_sha256": digest, "reproduction_id": f"ce-{digest}"}


def _shrink_candidates(value: Any, *, depth: int, max_depth: int) -> Iterator[Any]:
    """Yield deterministic, JSON-like structural simplifications.

    This generator only constructs values.  It never imports, builds, or
    executes a target; the caller-owned predicate is the explicit oracle.
    """
    if depth >= max_depth:
        return
    if isinstance(value, dict):
        keys = sorted(value, key=lambda item: _canonical(item))
        for key in keys:
            candidate = dict(value)
            del candidate[key]
            yield candidate
        for key in keys:
            for reduced in _shrink_candidates(value[key], depth=depth + 1, max_depth=max_depth):
                candidate = dict(value)
                candidate[key] = reduced
                yield candidate
    elif isinstance(value, list):
        if value:
            yield []
            for index in range(len(value)):
                yield value[:index] + value[index + 1 :]
            for index, item in enumerate(value):
                for reduced in _shrink_candidates(item, depth=depth + 1, max_depth=max_depth):
                    candidate = list(value)
                    candidate[index] = reduced
                    yield candidate
    elif isinstance(value, str):
        if value:
            yield ""
            if len(value) > 1:
                midpoint = len(value) // 2
                yield value[:midpoint]
                yield value[midpoint:]
            # Single-character deletions let the greedy loop peel framing
            # bytes/text around a failure token when halving would destroy it.
            for index in range(len(value)):
                yield value[:index] + value[index + 1 :]
    elif isinstance(value, bool):
        if value:
            yield False
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if value != 0:
            yield 0
            yield value / 2 if isinstance(value, float) else value // 2


def reduce_counterexample(
    input_value: Any,
    is_failure: Callable[[Any], bool],
    *,
    max_attempts: int = 1_000,
    max_depth: int = 32,
) -> dict[str, Any]:
    """Greedily reduce a known failing input using an explicit external oracle.

    The reducer is deliberately a harness boundary: it never executes a
    reconstructed/original program.  ``is_failure`` must return a real bool;
    exceptions and non-bool results fail closed.  Results include stable input
    hashes so a minimized case can be handed to an independent replay tool.
    """
    schema = "counterexample-reduction.v1"
    if not callable(is_failure):
        return {"schema": schema, "status": "invalid", "original": input_value, "reduced": input_value, "attempts": 0, "accepted": 0, "errors": [{"code": "failure_oracle_not_callable"}], "limitations": ["não executa alvo; o oracle é fornecido pelo chamador", "redução gulosa não prova minimalidade global"]}
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        return {"schema": schema, "status": "invalid", "original": input_value, "reduced": input_value, "attempts": 0, "accepted": 0, "errors": [{"code": "max_attempts_invalid"}], "limitations": ["não executa alvo; o oracle é fornecido pelo chamador", "redução gulosa não prova minimalidade global"]}
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
        return {"schema": schema, "status": "invalid", "original": input_value, "reduced": input_value, "attempts": 0, "accepted": 0, "errors": [{"code": "max_depth_invalid"}], "limitations": ["não executa alvo; o oracle é fornecido pelo chamador", "redução gulosa não prova minimalidade global"]}

    limitations = ["não executa alvo; o oracle é fornecido pelo chamador", "redução gulosa não prova minimalidade global", "hash identifica a representação canônica, não autenticidade"]
    attempts = 0
    accepted = 0

    def check(candidate: Any) -> tuple[bool, dict[str, Any] | None]:
        nonlocal attempts
        if attempts >= max_attempts:
            return False, None
        attempts += 1
        try:
            result = is_failure(candidate)
        except Exception as exc:  # pragma: no cover - exact exception varies by harness
            return False, {"code": "failure_oracle_error", "detail": type(exc).__name__}
        if not isinstance(result, bool):
            return False, {"code": "failure_oracle_must_return_bool", "detail": type(result).__name__}
        return result, None

    original_failed, error = check(input_value)
    if error:
        return {"schema": schema, "status": "invalid", "original": input_value, "reduced": input_value, "attempts": attempts, "accepted": accepted, "errors": [error], "limitations": limitations, **_counterexample_identity(input_value)}
    if not original_failed:
        return {"schema": schema, "status": "not_a_counterexample", "original": input_value, "reduced": input_value, "attempts": attempts, "accepted": accepted, "errors": [{"code": "oracle_did_not_confirm_failure"}], "limitations": limitations, **_counterexample_identity(input_value)}

    current = input_value
    seen = {_canonical(current)}
    budget_exhausted = False
    while True:
        changed = False
        for candidate in _shrink_candidates(current, depth=0, max_depth=max_depth):
            key = _canonical(candidate)
            if key in seen:
                continue
            seen.add(key)
            if attempts >= max_attempts:
                budget_exhausted = True
                break
            failed, error = check(candidate)
            if error:
                return {"schema": schema, "status": "invalid", "original": input_value, "reduced": current, "attempts": attempts, "accepted": accepted, "errors": [error], "limitations": limitations, **_counterexample_identity(current)}
            if failed:
                current = candidate
                accepted += 1
                changed = True
                break
        if budget_exhausted or not changed:
            break
    status = "budget_exhausted" if budget_exhausted else "reduced" if accepted else "unchanged"
    return {"schema": schema, "status": status, "original": input_value, "reduced": current, "attempts": attempts, "accepted": accepted, "errors": [], "limitations": limitations, "original_identity": _counterexample_identity(input_value), "reduced_identity": _counterexample_identity(current)}


def compare_observations(original: list[dict[str, Any]], reconstructed: list[dict[str, Any]], *, max_observations: int = 100_000) -> dict[str, Any]:
    """Compara por input/saída/efeitos/exceção e preserva contraexemplos."""
    schema = "differential-observation.v1"
    if not isinstance(original, list) or not isinstance(reconstructed, list):
        return {"schema": schema, "status": "invalid", "matched": 0, "mismatches": [], "summary": {"original": len(original) if isinstance(original, list) else 0, "reconstructed": len(reconstructed) if isinstance(reconstructed, list) else 0, "matched": 0, "mismatches": 0}, "errors": [{"code": "observations_must_be_lists"}], "limitations": ["não executa alvos", "não prova equivalência universal"]}
    if not isinstance(max_observations, int) or isinstance(max_observations, bool) or max_observations < 1:
        return {"schema": schema, "status": "invalid", "matched": 0, "mismatches": [], "summary": {"original": len(original), "reconstructed": len(reconstructed), "matched": 0, "mismatches": 0}, "errors": [{"code": "max_observations_invalid"}], "limitations": ["não executa alvos", "não prova equivalência universal"]}
    errors: list[dict[str, Any]] = []
    if len(original) > max_observations or len(reconstructed) > max_observations:
        errors.append({"code": "observation_budget_exceeded", "max": max_observations, "original": len(original), "reconstructed": len(reconstructed)})
    def index_rows(rows: list[dict[str, Any]], side: str) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(rows[:max_observations]):
            if not isinstance(item, dict):
                errors.append({"side": side, "index": index, "code": "observation_not_object"})
                continue
            if "input" not in item:
                errors.append({"side": side, "index": index, "code": "observation_input_missing"})
                continue
            key = _canonical(item.get("input"))
            if key in indexed:
                errors.append({"side": side, "index": index, "code": "duplicate_observation_input"})
                continue
            indexed[key] = item
        return indexed
    original_by_input = index_rows(original, "original")
    by_input = index_rows(reconstructed, "reconstructed")
    if errors:
        return {"schema": schema, "status": "invalid", "matched": 0, "mismatches": [], "summary": {"original": len(original), "reconstructed": len(reconstructed), "matched": 0, "mismatches": 0}, "errors": errors, "limitations": ["não executa alvos", "duplicatas não são descartadas silenciosamente", "não prova equivalência universal"]}
    mismatches: list[dict[str, Any]] = []
    matched = 0
    for observed in original:
        key = _canonical(observed.get("input"))
        candidate = by_input.get(key)
        if candidate is None:
            mismatches.append({"input": observed.get("input"), **_counterexample_identity(observed.get("input")), "kind": "missing_reconstruction", "original": observed})
            continue
        comparable = ("output", "effects", "exception")
        differences = [field for field in comparable if _canonical(observed.get(field)) != _canonical(candidate.get(field))]
        if differences:
            mismatches.append({"input": observed.get("input"), **_counterexample_identity(observed.get("input")), "kind": "behavior_mismatch", "fields": differences, "original": observed, "reconstructed": candidate})
        else:
            matched += 1
    for candidate in reconstructed:
        if _canonical(candidate.get("input")) not in original_by_input:
            mismatches.append({"input": candidate.get("input"), **_counterexample_identity(candidate.get("input")), "kind": "unexpected_reconstruction", "reconstructed": candidate})
    return {
        "schema": schema,
        "matched": matched,
        "mismatches": mismatches,
        "summary": {"original": len(original), "reconstructed": len(reconstructed), "matched": matched, "mismatches": len(mismatches)},
        "status": "equivalent_on_observations" if not mismatches else "counterexamples_found",
        "confidence_kind": "empirical_observation",
        "limitations": ["não prova equivalência universal", "qualidade depende da cobertura das entradas/efeitos observados", "UNSAT ou ausência de caso não é prova de segurança"],
    }


def write_differential_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
