"""Indicadores estáticos de risco com caminho de evidência e abstenção."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


RULES: dict[str, tuple[str, str]] = {
    "eval": ("high", "avaliação dinâmica de texto"),
    "exec": ("high", "execução dinâmica de código"),
    "os.system": ("high", "shell command potencial"),
    "subprocess.call": ("medium", "processo externo"),
    "subprocess.run": ("medium", "processo externo"),
    "subprocess.Popen": ("medium", "processo externo"),
    "pickle.loads": ("high", "desserialização potencialmente insegura"),
    "pickle.load": ("high", "desserialização potencialmente insegura"),
    "ctypes": ("medium", "acesso nativo fora do interpretador"),
}


_LIMITATIONS = [
    "indicador estático não prova vulnerabilidade",
    "alcançabilidade permanece unknown",
    "sanitização e contexto exigem análise de fluxo/teste",
]


def _invalid_report(detail: str, *, code: str = "source_report_invalid") -> dict[str, Any]:
    return {
        "schema": "python-risk-audit.v1",
        "status": "invalid",
        "indicators": [],
        "errors": [{"code": code, "detail": detail}],
        "summary": {"total": 0, "high": 0, "medium": 0, "source_errors": 0},
        "limitations": list(_LIMITATIONS),
    }


def audit_source_risks(source_report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(source_report, dict):
        return _invalid_report("object_required")
    calls = source_report.get("calls")
    if not isinstance(calls, list):
        return _invalid_report("calls_must_be_list")
    source_errors = source_report.get("errors", [])
    if not isinstance(source_errors, list):
        return _invalid_report("errors_must_be_list")
    indicators: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        if not isinstance(call, dict):
            errors.append({"code": "call_not_object", "index": index})
            continue
        callee = call.get("callee")
        if not isinstance(callee, str) or not callee.strip():
            errors.append({"code": "call_callee_invalid", "index": index})
            continue
        rule_key = callee if callee in RULES else next((key for key in RULES if callee.endswith(key)), None)
        if not rule_key:
            continue
        severity, reason = RULES[rule_key]
        indicators.append({
            "rule": rule_key,
            "severity": severity,
            "reason": reason,
            "source": call.get("source", ""),
            "line": call.get("line"),
            "caller": call.get("caller", ""),
            "callee": callee,
            "state": "static_indicator",
            "reachable": "unknown",
            "confidence_kind": "heuristic",
            "requires_validation": True,
        })
    if errors:
        return {
            "schema": "python-risk-audit.v1",
            "status": "invalid",
            "indicators": indicators,
            "errors": errors,
            "summary": {"total": len(indicators), "high": sum(item["severity"] == "high" for item in indicators), "medium": sum(item["severity"] == "medium" for item in indicators), "source_errors": len(source_errors)},
            "limitations": list(_LIMITATIONS),
        }
    status = "partial" if source_errors else "complete"
    return {
        "schema": "python-risk-audit.v1",
        "status": status,
        "indicators": indicators,
        "errors": [],
        "summary": {
            "total": len(indicators),
            "high": sum(item["severity"] == "high" for item in indicators),
            "medium": sum(item["severity"] == "medium" for item in indicators),
            "source_errors": len(source_errors),
        },
        "limitations": list(_LIMITATIONS),
    }


def write_risk_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
