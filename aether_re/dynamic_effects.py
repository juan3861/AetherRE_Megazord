"""Validador de efeitos dinâmicos coletados externamente sob uma política."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


SCHEMA = "dynamic-effects-validation.v1"
FILE_EVENTS = {"file_read", "file_write", "file_delete", "file_open"}
NETWORK_EVENTS = {"network_connect", "network_send", "network_receive"}
PROCESS_EVENTS = {"process_spawn", "process_exit"}


def validate_effects(
    events: list[dict[str, Any]],
    *,
    allowed_roots: list[Path] | None = None,
    network_enabled: bool = False,
    writable_project: bool = False,
    max_events: int = 100_000,
) -> dict[str, Any]:
    """Check scope/policy of supplied observations; never inspects the target by running it."""
    if not isinstance(events, list):
        return {"schema": SCHEMA, "status": "invalid", "events": [], "issues": [{"code": "events_not_list"}], "summary": {"received": 0, "accepted": 0, "issues": 1}, "limitations": ["efeitos são observações fornecidas por collector externo", "nenhum alvo foi executado"]}
    if not isinstance(max_events, int) or isinstance(max_events, bool) or max_events < 1 or max_events > 1_000_000:
        return {"schema": SCHEMA, "status": "invalid", "events": [], "issues": [{"code": "max_events_invalid"}], "summary": {"received": len(events), "accepted": 0, "issues": 1}, "limitations": ["efeitos são observações fornecidas por collector externo", "nenhum alvo foi executado"]}
    if allowed_roots is not None and not isinstance(allowed_roots, list):
        return {"schema": SCHEMA, "status": "invalid", "events": [], "issues": [{"code": "allowed_roots_not_list"}], "summary": {"received": len(events), "accepted": 0, "issues": 1}, "limitations": ["efeitos são observações fornecidas por collector externo", "nenhum alvo foi executado"]}
    if not isinstance(network_enabled, bool) or not isinstance(writable_project, bool):
        return {"schema": SCHEMA, "status": "invalid", "events": [], "issues": [{"code": "policy_flag_invalid"}], "summary": {"received": len(events), "accepted": 0, "issues": 1}, "limitations": ["efeitos são observações fornecidas por collector externo", "nenhum alvo foi executado"]}
    roots: list[Path] = []
    for item in allowed_roots or []:
        if not isinstance(item, Path):
            return {"schema": SCHEMA, "status": "invalid", "events": [], "issues": [{"code": "allowed_root_invalid"}], "summary": {"received": len(events), "accepted": 0, "issues": 1}, "limitations": ["efeitos são observações fornecidas por collector externo", "nenhum alvo foi executado"]}
        try:
            roots.append(item.resolve())
        except (OSError, ValueError):
            return {"schema": SCHEMA, "status": "invalid", "events": [], "issues": [{"code": "allowed_root_invalid", "path": str(item)}], "summary": {"received": len(events), "accepted": 0, "issues": 1}, "limitations": ["efeitos são observações fornecidas por collector externo", "nenhum alvo foi executado"]}
    issues: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    if len(events) > max_events:
        issues.append({"code": "event_budget_exceeded", "received": len(events), "max_events": max_events})
    for index, event in enumerate(events[:max_events]):
        if not isinstance(event, dict):
            issues.append({"index": index, "code": "event_not_object"})
            continue
        raw_kind = event.get("event", "")
        if not isinstance(raw_kind, str):
            issues.append({"index": index, "code": "event_type_invalid"})
            continue
        kind = raw_kind.strip()
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            issues.append({"index": index, "code": "payload_not_object"})
            payload = {}
        else:
            try:
                json.dumps(payload, ensure_ascii=False, allow_nan=False)
            except (TypeError, ValueError):
                issues.append({"index": index, "code": "payload_not_serializable"})
                payload = {}
        normalized = {"seq": event.get("seq"), "event": kind, "process_id": str(event.get("process_id", "")), "thread_id": str(event.get("thread_id", "")), "path": event.get("path"), "address": event.get("address"), "network": event.get("network"), "payload": payload}
        if not kind:
            issues.append({"index": index, "code": "event_type_missing"})
            continue
        if kind in NETWORK_EVENTS and not network_enabled:
            issues.append({"index": index, "code": "network_policy_violation", "event": kind})
        if kind in FILE_EVENTS:
            raw_path = event.get("path") or payload.get("path")
            if not raw_path:
                issues.append({"index": index, "code": "file_path_missing", "event": kind})
            elif not isinstance(raw_path, (str, Path)):
                issues.append({"index": index, "code": "file_path_invalid", "path": repr(raw_path)})
            elif roots:
                try:
                    observed_path = Path(str(raw_path)).expanduser().resolve()
                    if not any(_is_under(observed_path, root) for root in roots):
                        issues.append({"index": index, "code": "path_outside_scope", "path": str(raw_path)})
                except (OSError, ValueError):
                    issues.append({"index": index, "code": "file_path_invalid", "path": str(raw_path)})
            if kind in {"file_write", "file_delete"} and not writable_project:
                issues.append({"index": index, "code": "write_policy_violation", "event": kind})
        accepted.append(normalized)
    status = "violation" if issues else "valid"
    return {"schema": SCHEMA, "status": status, "events": accepted, "issues": issues, "policy": {"allowed_roots": [str(item) for item in roots], "network_enabled": network_enabled, "writable_project": writable_project, "max_events": max_events}, "summary": {"received": len(events), "accepted": len(accepted), "issues": len(issues)}, "limitations": ["efeitos são observações fornecidas por collector externo", "ausência de evento não prova ausência do efeito", "path textual pode sofrer alias/symlink no collector", "nenhum alvo foi executado"]}


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def write_effects_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
