import json
from argparse import Namespace

from aether_re.trace import validate_trace, validate_trace_document
from megazord import cmd_trace_validate


def test_trace_validator_detects_loss_and_preserves_metadata():
    report = validate_trace([
        {"seq": 1, "timestamp_ns": 10, "thread_id": 2, "process_id": 3, "event": "enter", "module": "a.dll", "payload": {"rva": "0x10"}},
        {"seq": 3, "timestamp_ns": 30, "thread_id": 2, "process_id": 3, "event": "leave", "module": "a.dll"},
    ])
    assert report["status"] == "partial"
    assert report["summary"] == {"received": 2, "accepted": 2, "issues": 1}
    assert report["issues"][0]["kind"] == "sequence_gap"
    assert report["events"][0]["payload"]["rva"] == "0x10"


def test_trace_validator_fail_closes_malformed_records_and_timestamp():
    report = validate_trace([
        "not-an-event",
        {"seq": "x", "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "m"},
        {"seq": 2, "timestamp_ns": "x", "thread_id": "t", "process_id": "p", "event": "call", "module": "m"},
        {"seq": 3, "timestamp_ns": 3, "thread_id": "t", "process_id": "p", "event": "call", "module": "m", "payload": []},
    ])
    assert report["status"] == "partial"
    assert report["summary"]["accepted"] == 1
    assert {item["kind"] for item in report["issues"]} >= {"event_not_object", "invalid_sequence", "invalid_timestamp", "payload_not_object"}
    assert report["events"][0]["payload"] == {}


def test_trace_validator_refuses_unbounded_budget_and_non_list():
    budget = validate_trace([], max_events=0)
    assert budget["status"] == "invalid"
    assert budget["issues"][0]["kind"] == "max_events_invalid"
    shape = validate_trace({})  # type: ignore[arg-type]
    assert shape["status"] == "invalid"
    assert shape["issues"][0]["kind"] == "events_not_list"
    assert validate_trace([])["status"] == "insufficient_data"


def test_trace_validator_marks_truncation_without_false_complete():
    event = {"seq": 1, "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "m"}
    report = validate_trace([event, {**event, "seq": 2}], max_events=1)
    assert report["status"] == "partial"
    assert report["summary"]["truncated"] is True
    assert report["summary"]["received"] == 2


def test_trace_cli_rejects_unreadable_input_without_traceback(tmp_path):
    source = tmp_path / "trace.json"
    out = tmp_path / "report.json"
    source.write_text("{", encoding="utf-8")
    code = cmd_trace_validate(Namespace(input=str(source), out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["issues"][0]["kind"] == "input_unreadable"


def test_trace_document_preserves_metadata_and_rejects_bad_target_hash():
    event = {"seq": 1, "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "m"}
    report = validate_trace_document({"schema": "dynamic-trace.v1", "target_sha256": "a" * 64, "run_id": "r1", "collector": "vm", "events": [event]})
    assert report["status"] == "complete"
    assert report["trace_metadata"]["target_sha256"] == "a" * 64
    invalid = validate_trace_document({"schema": "dynamic-trace.v1", "target_sha256": "bad", "events": [event]})
    assert invalid["status"] == "invalid"
    assert invalid["issues"][0]["kind"] == "target_hash_invalid"


def test_trace_document_rejects_unknown_schema():
    report = validate_trace_document({"schema": "other.v1", "events": []})
    assert report["status"] == "invalid"
    assert report["issues"][0]["kind"] == "trace_schema_invalid"


def test_trace_validator_rejects_boolean_sequence_and_invalid_scalar_fields():
    report = validate_trace(
        [
            {"seq": True, "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "m"},
            {"seq": 2, "timestamp_ns": 2, "thread_id": None, "process_id": "p", "event": "call", "module": "m"},
        ]
    )
    assert report["status"] == "partial"
    assert report["summary"]["accepted"] == 0
    assert {item["kind"] for item in report["issues"]} >= {"invalid_sequence", "scalar_field_invalid"}


def test_trace_validator_rejects_coercive_numbers_empty_identity_and_time_reversal():
    report = validate_trace(
        [
            {"seq": 0, "timestamp_ns": 10, "thread_id": "t", "process_id": "p", "event": "call", "module": "m"},
            {"seq": 1, "timestamp_ns": 9, "thread_id": "", "process_id": "p", "event": "call", "module": "m", "payload": {"x": float("nan")}},
            {"seq": 2.0, "timestamp_ns": 11, "thread_id": "t", "process_id": "p", "event": "call", "module": "m"},
        ]
    )
    codes = {item["kind"] for item in report["issues"]}
    assert {"invalid_sequence", "timestamp_out_of_order", "scalar_field_invalid", "payload_not_serializable"} <= codes


def test_trace_validator_does_not_advance_continuity_on_invalid_scalar_record():
    valid = {"seq": 1, "timestamp_ns": 1, "thread_id": "t", "process_id": "p", "event": "call", "module": "m"}
    malformed = {**valid, "seq": 3, "thread_id": None}
    following = {**valid, "seq": 2, "timestamp_ns": 2}
    report = validate_trace([valid, malformed, following])
    assert report["summary"]["accepted"] == 2
    assert not any(item["kind"] == "out_of_order_or_duplicate" and item.get("index") == 2 for item in report["issues"])
