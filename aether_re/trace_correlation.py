"""Correlação conservadora entre eventos de trace e mapas estáticos."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .trace import validate_trace


SCHEMA = "dynamic-trace-correlation.v1"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_TRACE_EVENTS = 100_000


def _function_rows(report: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        return []
    values = report.get("functions", report.get("merged_functions", []))
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _matches_by_name(name: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lower = name.lower()
    return [row for row in rows if str(row.get("name", "")).lower() == lower or str(row.get("qualified_name", "")).lower() == lower or str(row.get("address", "")).lower() == lower]


def _matches_by_hints(name: str, address: str, module: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Resolve all supplied identity hints without letting one stale hint hide another.

    A trace may contain a source-level name while a stripped binary only has
    an address (or vice versa).  The previous ``name or address`` shortcut
    silently discarded the useful second hint.  Union both exact matches,
    deduplicate by canonical row content, and use a module hint only when the
    row actually declares a module so missing metadata remains explicit.
    """
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for hint in (name, address):
        if not hint:
            continue
        for row in _matches_by_name(hint, rows):
            key = json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)
            if key not in seen:
                seen.add(key)
                candidates.append(row)
    module_hint = module.strip().lower()
    if module_hint and candidates:
        declared = [row for row in candidates if str(row.get("module", "")).strip()]
        narrowed = [row for row in declared if str(row.get("module", "")).strip().lower() in {module_hint, module_hint.rsplit("/", 1)[-1], module_hint.rsplit("\\", 1)[-1]}]
        if narrowed:
            candidates = narrowed
    return candidates


def correlate_trace(
    trace: dict[str, Any],
    *,
    source_report: dict[str, Any] | None = None,
    binary_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Map supplied event metadata; never infer missing events or execute code."""
    if not isinstance(trace, dict) or trace.get("schema") != "dynamic-trace.v1":
        return {"schema": SCHEMA, "status": "invalid", "events": [], "issues": [{"code": "trace_schema_invalid"}], "limitations": ["não executa alvo"]}
    events = trace.get("events", [])
    if not isinstance(events, list):
        return {"schema": SCHEMA, "status": "invalid", "events": [], "issues": [{"code": "trace_events_invalid"}], "limitations": ["não executa alvo"]}
    issues: list[dict[str, Any]] = []
    # Correlation is downstream of collection, so it must not trust a
    # collector's declared ``status=complete``.  Re-validate sequence,
    # timestamps, scalar identities and the event budget before mapping any
    # metadata; otherwise a trace with a gap could be promoted to complete.
    trace_contract = validate_trace(events, max_events=_MAX_TRACE_EVENTS)
    contract_issues: list[dict[str, Any]] = []
    # An empty trace is a lack of data, not a malformed contract.  Preserve
    # the dedicated ``insufficient_data`` outcome for that case.
    if events and trace_contract.get("status") != "complete":
        contract_issues.append(
            {
                "code": "trace_contract_not_complete",
                "status": trace_contract.get("status"),
                "accepted": trace_contract.get("summary", {}).get("accepted", 0),
                "received": trace_contract.get("summary", {}).get("received", len(events)),
            }
        )
        for contract_issue in trace_contract.get("issues", []):
            if isinstance(contract_issue, dict):
                contract_issues.append({"code": "trace_contract_issue", **contract_issue})
    for label, report in (("source", source_report), ("binary", binary_report)):
        if report is not None and not isinstance(report, dict):
            issues.append({"code": f"{label}_report_invalid", "detail": "object_required"})
        elif isinstance(report, dict):
            values = report.get("functions", report.get("merged_functions", []))
            if not isinstance(values, list):
                issues.append({"code": f"{label}_functions_invalid", "detail": "list_required"})
    source_rows = _function_rows(source_report)
    binary_rows = _function_rows(binary_report)
    target_issues: list[dict[str, Any]] = []
    trace_hash = trace.get("target_sha256")
    binary_hash = binary_report.get("target_sha256") if isinstance(binary_report, dict) else None
    if trace_hash is not None and (not isinstance(trace_hash, str) or not _SHA256_RE.fullmatch(trace_hash)):
        target_issues.append({"code": "trace_target_hash_invalid"})
    if binary_hash is not None and (not isinstance(binary_hash, str) or not _SHA256_RE.fullmatch(binary_hash)):
        target_issues.append({"code": "binary_target_hash_invalid"})
    if trace_hash and binary_hash and trace_hash != binary_hash:
        target_issues.append({"code": "target_hash_mismatch", "trace": trace_hash, "binary": binary_hash})
    # Apply the same hard bound to mapping that validation applies to
    # collection.  A hostile report must not force an unbounded correlation
    # loop merely because it supplied a large JSON array.
    events_to_map = events[:_MAX_TRACE_EVENTS]
    mapped: list[dict[str, Any]] = []
    event_issues: list[dict[str, Any]] = []
    required_event_fields = ("seq", "timestamp_ns", "thread_id", "process_id", "event", "module")
    for index, event in enumerate(events_to_map):
        if not isinstance(event, dict):
            mapped.append({"status": "invalid_event"})
            event_issues.append({"index": index, "code": "event_not_object"})
            continue
        missing = [field for field in required_event_fields if field not in event]
        if missing:
            mapped.append({"status": "invalid_event", "missing_fields": missing})
            event_issues.append({"index": index, "code": "event_fields_missing", "fields": missing})
            continue
        if isinstance(event.get("seq"), bool) or not isinstance(event.get("seq"), int) or event.get("seq") < 0:
            mapped.append({"status": "invalid_event"})
            event_issues.append({"index": index, "code": "event_sequence_invalid"})
            continue
        if isinstance(event.get("timestamp_ns"), bool) or not isinstance(event.get("timestamp_ns"), int) or event.get("timestamp_ns") < 0:
            mapped.append({"status": "invalid_event"})
            event_issues.append({"index": index, "code": "event_timestamp_invalid"})
            continue
        scalar_invalid = [field for field in ("thread_id", "process_id", "event", "module") if event.get(field) is None or isinstance(event.get(field), (bool, list, dict)) or (field in {"event", "module"} and not str(event.get(field)).strip())]
        if scalar_invalid:
            mapped.append({"status": "invalid_event"})
            event_issues.append({"index": index, "code": "event_scalar_invalid", "fields": scalar_invalid})
            continue
        payload = event.get("payload", {}) if isinstance(event.get("payload", {}), dict) else {}
        if "payload" in event and not isinstance(event.get("payload"), dict):
            event_issues.append({"index": index, "code": "event_payload_invalid"})
        name = str(payload.get("function") or payload.get("symbol") or payload.get("name") or "")
        address = str(payload.get("address") or payload.get("rva") or "")
        module = str(event.get("module"))
        source_matches = _matches_by_hints(name, address, module, source_rows) if name or address else []
        binary_matches = _matches_by_hints(name, address, module, binary_rows) if name or address else []
        source_status = "matched" if len(source_matches) == 1 else "ambiguous" if len(source_matches) > 1 else "unmatched"
        binary_status = "matched" if len(binary_matches) == 1 else "ambiguous" if len(binary_matches) > 1 else "unmatched"
        mapped.append({"seq": event.get("seq"), "event": event.get("event"), "module": event.get("module"), "function_hint": name or None, "address_hint": address or None, "source": {"status": source_status, "matches": source_matches[:20]}, "binary": {"status": binary_status, "matches": binary_matches[:20]}, "requires_validation": True})
    issues.extend(target_issues)
    # Keep target identity failures first for deterministic diagnostics, then
    # add continuity/contract failures discovered before mapping.
    issues.extend(contract_issues)
    issues.extend(event_issues)
    statuses = [item for item in mapped if item.get("status") != "invalid_event"]
    reference_reports_supplied = source_report is not None or binary_report is not None
    # A syntactically valid trace without either static map is not a completed
    # correlation.  Preserve the events, but explicitly downgrade the result
    # so a caller cannot mistake trace validation for source/binary mapping.
    correlation_status = "invalid" if issues else "insufficient_data" if not mapped else "partial" if trace.get("status") != "complete" or not reference_reports_supplied else "complete"
    return {
        "schema": SCHEMA,
        "status": correlation_status,
        "events": mapped,
        "issues": issues,
        "summary": {"events": len(mapped), "received_events": len(events), "truncated": len(events) > _MAX_TRACE_EVENTS, "reference_reports_supplied": reference_reports_supplied, "invalid_events": sum(item.get("status") == "invalid_event" for item in mapped), "source_matched": sum(item.get("source", {}).get("status") == "matched" for item in statuses), "binary_matched": sum(item.get("binary", {}).get("status") == "matched" for item in statuses), "unmatched": sum(item.get("source", {}).get("status") == "unmatched" and item.get("binary", {}).get("status") == "unmatched" for item in statuses)},
        "trace_contract": {
            "status": trace_contract.get("status"),
            "received": trace_contract.get("summary", {}).get("received", len(events)),
            "accepted": trace_contract.get("summary", {}).get("accepted", 0),
            "issues": trace_contract.get("summary", {}).get("issues", len(trace_contract.get("issues", []))),
        },
        "limitations": ["correlação por nome/endereço fornecido no payload", "trace sem relatório fonte/binário não é correlação completa", "não inventa funções para eventos sem metadados", "matching não prova causalidade nem equivalência", "trace parcial permanece parcial", "valida contrato/continuidade antes de correlacionar", "nenhum alvo foi executado"]
    }


def write_trace_correlation(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
