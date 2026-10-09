"""Contrato e validador de traces dinâmicos; não executa o alvo."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def validate_trace(events: list[dict[str, Any]], *, max_events: int = 100_000) -> dict[str, Any]:
    """Validate externally supplied events without executing a target.

    Collectors are untrusted inputs: malformed JSON objects, hostile integer
    conversions and unbounded traces must be represented as evidence issues,
    never as a validator crash or an implicit successful empty run.
    """
    if not isinstance(events, list):
        return {
            "schema": "dynamic-trace.v1",
            "events": [],
            "issues": [{"kind": "events_not_list"}],
            "status": "invalid",
            "summary": {"received": 0, "accepted": 0, "issues": 1},
            "limitations": ["valida contrato/continuidade, não prova causalidade", "nenhum alvo foi executado"],
        }
    if not isinstance(max_events, int) or isinstance(max_events, bool) or max_events < 1:
        return {
            "schema": "dynamic-trace.v1",
            "events": [],
            "issues": [{"kind": "max_events_invalid"}],
            "status": "invalid",
            "summary": {"received": len(events), "accepted": 0, "issues": 1},
            "limitations": ["valida contrato/continuidade, não prova causalidade", "nenhum alvo foi executado"],
        }
    normalized: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    previous_seq: int | None = None
    previous_timestamp: int | None = None
    received = len(events)
    if received > max_events:
        issues.append({"kind": "event_budget_exceeded", "received": received, "max": max_events})
    for index, raw in enumerate(events[:max_events]):
        if not isinstance(raw, dict):
            issues.append({"index": index, "kind": "event_not_object"})
            continue
        missing = [field for field in ("seq", "timestamp_ns", "thread_id", "process_id", "event", "module") if field not in raw]
        if missing:
            issues.append({"index": index, "kind": "missing_fields", "fields": missing})
            continue
        try:
            if isinstance(raw["seq"], bool) or not isinstance(raw["seq"], int):
                raise ValueError("integer_sequence_required")
            seq = raw["seq"]
        except (TypeError, ValueError, OverflowError):
            issues.append({"index": index, "kind": "invalid_sequence"})
            continue
        try:
            if isinstance(raw["timestamp_ns"], bool) or not isinstance(raw["timestamp_ns"], int):
                raise ValueError("integer_timestamp_required")
            timestamp_ns = raw["timestamp_ns"]
        except (TypeError, ValueError, OverflowError):
            issues.append({"index": index, "kind": "invalid_timestamp"})
            continue
        if seq < 0:
            issues.append({"index": index, "kind": "invalid_sequence", "detail": "negative"})
            continue
        if timestamp_ns < 0:
            issues.append({"index": index, "kind": "invalid_timestamp", "detail": "negative"})
            continue
        if previous_seq is not None:
            if seq <= previous_seq:
                issues.append({"index": index, "kind": "out_of_order_or_duplicate", "previous": previous_seq, "current": seq})
            elif seq > previous_seq + 1:
                issues.append({"index": index, "kind": "sequence_gap", "from": previous_seq + 1, "to": seq - 1})
        if previous_timestamp is not None and timestamp_ns < previous_timestamp:
            issues.append({"index": index, "kind": "timestamp_out_of_order", "previous": previous_timestamp, "current": timestamp_ns})
        payload = raw.get("payload", {})
        if not isinstance(payload, dict):
            issues.append({"index": index, "kind": "payload_not_object"})
            payload = {}
        else:
            try:
                json.dumps(payload, ensure_ascii=False, allow_nan=False)
            except (TypeError, ValueError):
                issues.append({"index": index, "kind": "payload_not_serializable"})
                payload = {}
        invalid_scalar_fields = [
            field
            for field in ("thread_id", "process_id", "event", "module")
            if raw.get(field) is None or isinstance(raw.get(field), (bool, list, dict)) or (isinstance(raw.get(field), str) and not raw[field].strip())
        ]
        if invalid_scalar_fields:
            issues.append({"index": index, "kind": "scalar_field_invalid", "fields": invalid_scalar_fields})
            continue
        # A malformed scalar record must not advance the continuity chain and
        # make a later valid record look like a false gap/duplicate.
        previous_seq = seq
        previous_timestamp = timestamp_ns
        normalized.append({
            "seq": seq,
            "timestamp_ns": timestamp_ns,
            "thread_id": str(raw["thread_id"]),
            "process_id": str(raw["process_id"]),
            "event": str(raw["event"]),
            "module": str(raw["module"]),
            "payload": payload,
        })
    summary = {"received": received, "accepted": len(normalized), "issues": len(issues)}
    if received > max_events:
        summary["truncated"] = True
    status = "partial" if issues else "insufficient_data" if not normalized else "complete"
    return {
        "schema": "dynamic-trace.v1",
        "events": normalized,
        "issues": issues,
        "status": status,
        "summary": summary,
        "limitations": ["valida contrato/continuidade, não prova causalidade", "eventos perdidos podem ser indistinguíveis de filtros do collector", "anti-debug e efeitos de observação permanecem fora deste validador", "nenhum alvo foi executado"],
    }


def validate_trace_document(document: Any, *, max_events: int = 100_000) -> dict[str, Any]:
    """Validate a trace envelope while retaining chain-of-custody metadata."""
    if not isinstance(document, dict):
        return validate_trace(document, max_events=max_events)
    if document.get("schema") not in (None, "dynamic-trace.v1"):
        return {
            "schema": "dynamic-trace.v1",
            "events": [],
            "issues": [{"kind": "trace_schema_invalid", "received": document.get("schema")}],
            "status": "invalid",
            "summary": {"received": 0, "accepted": 0, "issues": 1},
            "limitations": ["valida contrato/continuidade, não prova causalidade", "nenhum alvo foi executado"],
        }
    report = validate_trace(document.get("events"), max_events=max_events)
    metadata = {key: document[key] for key in ("target_sha256", "run_id", "collector", "isolation", "source") if key in document}
    if "target_sha256" in metadata and (not isinstance(metadata["target_sha256"], str) or not _SHA256_RE.fullmatch(metadata["target_sha256"])):
        report["issues"].append({"kind": "target_hash_invalid"})
        report["status"] = "invalid"
        report["summary"]["issues"] = len(report["issues"])
    if metadata:
        report["trace_metadata"] = metadata
    return report


def write_trace_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
