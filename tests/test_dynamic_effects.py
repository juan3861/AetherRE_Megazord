import json
from argparse import Namespace

from aether_re.dynamic_effects import validate_effects
from megazord import cmd_effects_validate


def test_effect_validation_accepts_scoped_read_and_rejects_network_write(tmp_path):
    events = [
        {"event": "file_read", "process_id": "p", "path": str(tmp_path / "input.bin")},
        {"event": "network_connect", "process_id": "p", "network": "10.0.0.1:443"},
        {"event": "file_write", "process_id": "p", "path": str(tmp_path / "out.bin")},
    ]
    report = validate_effects(events, allowed_roots=[tmp_path])
    assert report["status"] == "violation"
    codes = {item["code"] for item in report["issues"]}
    assert {"network_policy_violation", "write_policy_violation"} <= codes
    assert report["summary"]["accepted"] == 3


def test_effect_validation_rejects_path_outside_scope_and_budget(tmp_path):
    report = validate_effects(
        [{"event": "file_read", "path": "C:/outside.bin"}, {"event": "process_spawn"}],
        allowed_roots=[tmp_path],
        max_events=1,
    )
    assert report["status"] == "violation"
    assert any(item["code"] == "event_budget_exceeded" for item in report["issues"])
    assert any(item["code"] == "path_outside_scope" for item in report["issues"])


def test_effect_validation_fail_closes_shape_and_payload(tmp_path):
    shape = validate_effects({})  # type: ignore[arg-type]
    assert shape["status"] == "invalid"
    assert shape["issues"][0]["code"] == "events_not_list"
    budget = validate_effects([], max_events=0)
    assert budget["status"] == "invalid"
    assert budget["issues"][0]["code"] == "max_events_invalid"
    report = validate_effects([{"event": "file_read", "payload": [], "path": str(tmp_path / "in") }], allowed_roots=[tmp_path])
    assert report["status"] == "violation"
    assert any(item["code"] == "payload_not_object" for item in report["issues"])


def test_effects_cli_rejects_unreadable_input_without_traceback(tmp_path):
    source = tmp_path / "effects.json"
    out = tmp_path / "report.json"
    source.write_text("{", encoding="utf-8")
    code = cmd_effects_validate(Namespace(input=str(source), out=str(out), allowed_root=[], network_enabled=False, writable_project=False, max_events=10))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["issues"][0]["code"] == "input_unreadable"


def test_effects_rejects_policy_type_confusion_and_nonserializable_payload(tmp_path):
    policy = validate_effects([], allowed_roots="not-a-list")  # type: ignore[arg-type]
    assert policy["status"] == "invalid"
    assert policy["issues"][0]["code"] == "allowed_roots_not_list"
    policy = validate_effects([], network_enabled="off")  # type: ignore[arg-type]
    assert policy["status"] == "invalid"
    assert policy["issues"][0]["code"] == "policy_flag_invalid"
    report = validate_effects([{"event": "file_read", "path": ["bad"], "payload": {"x": float("nan")}}], allowed_roots=[tmp_path])
    codes = {item["code"] for item in report["issues"]}
    assert {"payload_not_serializable", "file_path_invalid"} <= codes
