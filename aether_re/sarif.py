"""Exportador SARIF 2.1.0 sem promover achados heurísticos a certezas."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _rule_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return cleaned[:120] or "megazord-finding"


def _level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity.lower(), "warning")


def report_to_sarif(report: dict[str, Any], *, tool_version: str = "unknown") -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    if not isinstance(report, dict):
        report = {}
        errors.append({"code": "report_must_be_object"})
    upstream_errors = report.get("errors", [])
    if upstream_errors is not None and not isinstance(upstream_errors, list):
        errors.append({"code": "errors_must_be_list"})
    elif isinstance(upstream_errors, list):
        errors.extend({"code": "upstream_error", "detail": item} for item in upstream_errors)

    def _records(name: str, value: Any) -> list[Any]:
        if value is None:
            return []
        if not isinstance(value, list):
            errors.append({"code": "records_must_be_list", "field": name})
            return []
        return value

    findings = _records("findings", report.get("findings", []))
    indicators = _records("indicators", report.get("indicators", []))
    # project-audit mantém relatórios especializados aninhados; expanda-os sem
    # descartar o contexto original.
    source_reports = report.get("source")
    if source_reports is not None and not isinstance(source_reports, dict):
        errors.append({"code": "nested_reports_must_be_object"})
    if isinstance(source_reports, dict):
        for nested in source_reports.values():
            if isinstance(nested, dict):
                findings = [*findings, *_records("nested.findings", nested.get("findings", []))]
                indicators = [*indicators, *_records("nested.indicators", nested.get("indicators", []))]
            elif nested is not None:
                errors.append({"code": "nested_report_must_be_object"})
    for finding in [*findings, *indicators]:
        if not isinstance(finding, dict):
            errors.append({"code": "finding_must_be_object"})
            continue
        engine = str(finding.get("engine") or finding.get("rule") or "megazord")
        title = str(finding.get("title") or finding.get("reason") or finding.get("rule") or "finding")
        rule_id = _rule_id(f"{engine}.{title}")
        severity_value = finding.get("severity", "warning")
        if not isinstance(severity_value, str):
            errors.append({"code": "severity_invalid", "rule_id": rule_id})
            severity = "warning"
        else:
            severity = severity_value
        rules.setdefault(rule_id, {"id": rule_id, "name": title, "shortDescription": {"text": title}, "properties": {"engine": engine, "heuristic": finding.get("confidence_kind") == "heuristic" or finding.get("state") in {"static_indicator", "candidate"}}})
        result: dict[str, Any] = {"ruleId": rule_id, "level": _level(severity), "message": {"text": str(finding.get("detail") or finding.get("reason") or title)}, "properties": {key: finding[key] for key in ("confidence", "confidence_kind", "state", "reachable", "requires_validation") if key in finding}}
        source = finding.get("source") or finding.get("path")
        line = finding.get("line")
        if source:
            region: dict[str, Any] = {}
            if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                region["startLine"] = line
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(source)}, **({"region": region} if region else {})}}]
        results.append(result)
    limitations = report.get("limitations", [])
    if not isinstance(limitations, list):
        errors.append({"code": "limitations_must_be_list"})
        limitations = []
    properties: dict[str, Any] = {"limitations": limitations, "source_status": "heuristic"}
    if errors:
        properties["errors"] = errors
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "AetherRE Megazord", "version": tool_version, "rules": sorted(rules.values(), key=lambda item: item["id"])}}, "results": results, "properties": properties}]}


def write_sarif(report: dict[str, Any], path: Path, *, tool_version: str = "unknown") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report_to_sarif(report, tool_version=tool_version), indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
