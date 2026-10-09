import json
from argparse import Namespace

import aether_re.trace_correlation as trace_correlation
from aether_re.trace_correlation import correlate_trace
from megazord import cmd_trace_correlate


def test_trace_correlation_preserves_ambiguity_and_unmatched_events():
    trace = {
        "schema": "dynamic-trace.v1",
        "status": "complete",
        "events": [
            {"seq": 1, "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "app", "payload": {"function": "run"}},
            {"seq": 2, "timestamp_ns": 2, "thread_id": "t", "process_id": "p", "event": "call", "module": "app", "payload": {"function": "missing"}},
        ],
    }
    source = {"functions": [{"name": "run", "qualified_name": "main.run", "line": 1}]}
    binary = {"target_sha256": "a" * 64, "merged_functions": [{"name": "run", "address": "0x1000"}]}
    report = correlate_trace(trace, source_report=source, binary_report=binary)
    assert report["status"] == "complete"
    assert report["summary"]["source_matched"] == 1
    assert report["summary"]["binary_matched"] == 1
    assert report["summary"]["unmatched"] == 1
    assert all(item["requires_validation"] for item in report["events"])


def test_trace_correlation_rejects_target_hash_mismatch():
    trace = {"schema": "dynamic-trace.v1", "status": "complete", "target_sha256": "a" * 64, "events": []}
    report = correlate_trace(trace, binary_report={"target_sha256": "b" * 64})
    assert report["status"] == "invalid"
    assert report["issues"][0]["code"] == "target_hash_mismatch"


def test_trace_correlation_does_not_call_empty_trace_complete():
    report = correlate_trace({"schema": "dynamic-trace.v1", "status": "complete", "events": []})
    assert report["status"] == "insufficient_data"


def test_trace_correlation_does_not_promote_sequence_gap_to_complete():
    trace = {
        "schema": "dynamic-trace.v1",
        "status": "complete",
        "events": [
            {"seq": 1, "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "app"},
            # The collector claims complete, but sequence 2 is absent.
            {"seq": 3, "timestamp_ns": 3, "thread_id": "t", "process_id": "p", "event": "return", "module": "app"},
        ],
    }
    report = correlate_trace(trace)
    assert report["status"] == "invalid"
    assert any(item["code"] == "trace_contract_issue" and item.get("kind") == "sequence_gap" for item in report["issues"])
    assert report["trace_contract"]["status"] == "partial"


def test_trace_correlation_applies_event_budget_before_mapping(monkeypatch):
    monkeypatch.setattr(trace_correlation, "_MAX_TRACE_EVENTS", 1)
    event = {"seq": 1, "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "app"}
    report = correlate_trace({"schema": "dynamic-trace.v1", "status": "complete", "events": [event, {**event, "seq": 2, "timestamp_ns": 2}]})
    assert report["status"] == "invalid"
    assert report["summary"]["events"] == 1
    assert report["summary"]["received_events"] == 2
    assert report["summary"]["truncated"] is True


def test_trace_correlation_uses_address_when_name_is_stripped_or_stale():
    trace = {
        "schema": "dynamic-trace.v1",
        "status": "complete",
        "events": [
            {
                "seq": 1,
                "timestamp_ns": 1,
                "thread_id": "t",
                "process_id": "p",
                "event": "call",
                "module": "app",
                "payload": {"function": "old_name", "address": "0x1000"},
            }
        ],
    }
    report = correlate_trace(trace, binary_report={"merged_functions": [{"name": "FUN_1000", "address": "0x1000"}]})
    assert report["status"] == "complete"
    assert report["summary"]["binary_matched"] == 1


def test_trace_correlation_without_reference_maps_is_not_complete():
    event = {"seq": 1, "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "app"}
    report = correlate_trace({"schema": "dynamic-trace.v1", "status": "complete", "events": [event]})
    assert report["status"] == "partial"
    assert report["summary"]["reference_reports_supplied"] is False


def test_trace_correlation_does_not_promote_malformed_events_or_reports():
    trace = {"schema": "dynamic-trace.v1", "status": "complete", "events": [{"seq": True}]}
    report = correlate_trace(trace, source_report=[], binary_report={"functions": {}})
    assert report["status"] == "invalid"
    codes = {item["code"] for item in report["issues"]}
    assert {"source_report_invalid", "binary_functions_invalid", "event_fields_missing"} <= codes
    assert report["summary"]["invalid_events"] == 1


def test_trace_correlation_cli_rejects_unreadable_input_without_traceback(tmp_path):
    source = tmp_path / "trace.json"
    binary = tmp_path / "binary.json"
    out = tmp_path / "correlation.json"
    source.write_text("{", encoding="utf-8")
    binary.write_text(json.dumps({"functions": []}), encoding="utf-8")
    code = cmd_trace_correlate(Namespace(input=str(source), source_report=None, binary_report=str(binary), out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["issues"][0]["code"] == "input_unreadable"
