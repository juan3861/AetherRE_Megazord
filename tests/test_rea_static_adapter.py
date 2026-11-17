import hashlib
import json
import sys
from pathlib import Path

from aether_re import rea_static


def _worker_verification(root: Path) -> dict:
    package = root / "rea-package"
    package.mkdir()
    entrypoint = package / "scripts" / "rea.mjs"
    entrypoint.parent.mkdir()
    entrypoint.write_text("// verified test double\n", encoding="utf-8")
    return {
        "verified": True,
        "issues": [],
        "paths": {
            "node": str(Path(sys.executable)),
            "package_root": str(package),
            "entrypoint": str(entrypoint),
        },
        "worker": {
            "name": "rea-agents-static-js-electron",
            "version": "6.4.0",
            "official_url": "https://registry.npmjs.org/rea-agents/-/rea-agents-6.4.0.tgz",
            "git_head": "a56f7bb668ab23fec8d33f7af353ac7ed2fe1895",
            "license_spdx": "MIT",
            "tarball_sha256": "a" * 64,
            "package_tree_sha256": "b" * 64,
            "dependencies_tree_sha256": "c" * 64,
            "node_version": "3.13.0-test",
            "node_sha256": "d" * 64,
            "limits": {
                "cpu_seconds": 30,
                "memory_bytes": 1024 * 1024 * 1024,
                "wall_seconds": 60,
                "output_bytes": 1024 * 1024,
                "node_heap_mb": 512,
                "analysis_timeout_ms": 30_000,
                "max_files": 100,
                "max_total_bytes": 1024 * 1024,
                "max_file_bytes": 256 * 1024,
            },
        },
    }


def _rea_result(input_path: str) -> dict:
    return {
        "input_path": input_path,
        "format": "directory",
        "root_artifact_sha256": "1" * 64,
        "inventory_manifest_id": "agm_" + "2" * 64,
        "inventory_graph_sha256": "3" * 64,
        "integrity_contradictions": [],
        "graph": {"schema": "javascript-application-graph.v1", "nodes": [], "edges": []},
        "summary": {"modules": 1, "electron": {"ipc_operations": 0}},
        "statistics": {"modules": 1, "parsed_javascript_files": 1, "parse_failures": 0},
        "limitations": ["static analysis only"],
        "semantic_graph": {"schema": "javascript-semantic-graph.v1", "nodes": [], "edges": []},
    }


def _rea_envelope(input_path: str) -> dict:
    result = _rea_result(input_path)
    return {
        "evidence_id": "ev_" + "4" * 64,
        "subject": {
            "name": input_path,
            "digest": {"sha256": result["root_artifact_sha256"]},
            "format": "directory",
            "architecture": None,
            "local_path": input_path,
        },
        "provider": {"id": "rea-javascript-application", "name": "REA JavaScript application analyzer", "version": "1"},
        "analysis_profile": None,
        "predicate_type": "rea.javascript-application-analysis",
        "operation": "analyze_javascript_application",
        "parameters": {"format": "directory", "integrity_policy": "fail"},
        "raw_result": None,
        "normalized_result": result,
        "confidence": "derived",
        "authority": "shipped-artifact",
        "environment": None,
        "limitations": ["static analysis only"],
        "locations": [],
        "evidence_links": [],
    }


def _fake_process(command, **kwargs):
    target = Path(command[3])
    assert target.is_dir()
    assert "analyze-javascript-application" in command
    assert "--json" in command
    assert kwargs["shell"] is False
    assert kwargs["output_limit_bytes"] == 1024 * 1024
    payload = json.dumps(_rea_envelope(str(target)), sort_keys=True)
    raw = payload.encode("utf-8")
    return {
        "returncode": 0,
        "stdout": payload,
        "stderr": "{\"rea_progress\":{\"phase\":\"complete\"}}\n",
        "timed_out": False,
        "resource_exceeded": False,
        "output_limit_exceeded": False,
        "output_bytes": len(raw),
        "captured_output_bytes": len(raw),
        "capture_complete": True,
        "process_tree_contained": True,
    }


def test_rea_static_adapter_fails_closed_when_toolchain_is_not_verified(tmp_path, monkeypatch):
    adapter = rea_static.ReaStaticJavaScriptAdapter()
    called = []
    monkeypatch.setattr(
        rea_static,
        "verify_rea_worker",
        lambda *_args, **_kwargs: {"verified": False, "issues": ["package_hash_mismatch"]},
    )
    monkeypatch.setattr(rea_static, "run_bounded", lambda *args, **kwargs: called.append(args))

    result = adapter.analyze(tmp_path / "app", tmp_path / "out")

    assert result["available"] is False
    assert result["executed"] is False
    assert result["produced_evidence"] is False
    assert result["error"] == "package_hash_mismatch"
    assert called == []
    assert not (tmp_path / "out").exists()


def test_candidate_provenance_hash_comparison_is_case_insensitive():
    worker = {"git_head": "abc123", "tarball_sha256": "a" * 64}
    candidate = {"gitHead": "abc123", "download_sha256": "A" * 64, "sri_match": True}

    assert rea_static._candidate_provenance_matches(candidate, worker) is True


def test_rea_static_adapter_snapshots_and_federates_two_static_engines(tmp_path, monkeypatch):
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text('{"name":"sample-electron","main":"main.js"}', encoding="utf-8")
    (app / "main.js").write_text("const { app } = require('electron'); app.whenReady();\n", encoding="utf-8")
    (app / "preload.js").write_text("contextBridge.exposeInMainWorld('api', {});\n", encoding="utf-8")
    out = tmp_path / "out"

    monkeypatch.setattr(rea_static, "verify_rea_worker", lambda *_args, **_kwargs: _worker_verification(tmp_path))
    bounded_calls = []

    def capture_bounded(*args, **kwargs):
        bounded_calls.append((args, kwargs))
        return _fake_process(*args, **kwargs)

    monkeypatch.setattr(rea_static, "run_bounded", capture_bounded)
    monkeypatch.setattr(
        rea_static,
        "analyze_project",
        lambda root: {"schema": "project-audit.v1", "status": "complete", "root": str(root), "source": {"javascript": {"modules": []}}, "summary": {"modules": 0}},
    )

    result = rea_static.ReaStaticJavaScriptAdapter().analyze(app, out)

    assert result["state"] == "succeeded"
    assert bounded_calls and bounded_calls[0][1]["require_process_tree"] is True
    assert result["produced_evidence"] is True
    rea_path = out / "rea-result.json"
    envelope_path = out / "rea-evidence-envelope.json"
    project_path = out / "aetherre-project-audit.json"
    report_path = out / "rea-federated-report.v1.json"
    assert rea_path.is_file() and envelope_path.is_file() and project_path.is_file() and report_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema"] == "rea-federated-report.v1"
    assert report["cross_engine_correlation"]["status"] == "not_attempted"
    assert report["artifact_correspondence"]["schema"] == "artifact-correspondence.v1"
    assert report["artifact_correspondence"]["semantic_graph_merge"] == "not_attempted"
    assert report["loss_ledger"]
    assert report["artifacts"][0]["sha256"] == hashlib.sha256(rea_path.read_bytes()).hexdigest()
    raw_envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    assert raw_envelope["normalized_result"] == json.loads(rea_path.read_text(encoding="utf-8"))
    envelope_artifact = next(item for item in report["artifacts"] if item["role"] == "raw_rea_evidence_envelope")
    assert envelope_artifact["sha256"] == hashlib.sha256(envelope_path.read_bytes()).hexdigest()
    normalized_artifact = next(item for item in report["artifacts"] if item["path"] == rea_path.name)
    assert normalized_artifact["role"] == "normalized_rea_analysis"
    snapshot = json.loads((out / "input_snapshot" / "manifest.json").read_text(encoding="utf-8"))
    assert snapshot["immutability"]["sealed"] is True


def test_rea_static_adapter_rejects_mismatched_evidence_subject(tmp_path, monkeypatch):
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.js").write_text("module.exports = 1;\n", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(rea_static, "verify_rea_worker", lambda *_args, **_kwargs: _worker_verification(tmp_path))

    def tampered_process(command, **_kwargs):
        target = Path(command[3])
        envelope = _rea_envelope(str(target))
        envelope["subject"]["digest"]["sha256"] = "f" * 64
        payload = json.dumps(envelope, sort_keys=True)
        return {
            "returncode": 0,
            "stdout": payload,
            "stderr": "",
            "timed_out": False,
            "resource_exceeded": False,
            "output_limit_exceeded": False,
            "output_bytes": len(payload.encode("utf-8")),
            "captured_output_bytes": len(payload.encode("utf-8")),
            "capture_complete": True,
            "process_tree_contained": True,
        }

    monkeypatch.setattr(rea_static, "run_bounded", tampered_process)
    result = rea_static.ReaStaticJavaScriptAdapter().analyze(app, out)

    assert result["state"] == "partial"
    assert result["error"] == "rea_evidence_subject_mismatch"
    assert result["produced_evidence"] is False
    assert not (out / "rea-result.json").exists()


def test_rea_static_adapter_marks_output_limit_as_failed_and_nonpromotable(tmp_path, monkeypatch):
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.js").write_text("module.exports = 1;\n", encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(rea_static, "verify_rea_worker", lambda *_args, **_kwargs: _worker_verification(tmp_path))
    monkeypatch.setattr(
        rea_static,
        "run_bounded",
        lambda *_args, **_kwargs: {
            "returncode": -1,
            "stdout": "{" + "x" * 100,
            "stderr": "",
            "timed_out": False,
            "resource_exceeded": True,
            "resource_kind": "output",
            "output_limit_exceeded": True,
            "output_bytes": 1024 * 1024 + 1,
            "captured_output_bytes": 1024 * 1024,
            "process_tree_contained": True,
        },
    )

    result = rea_static.ReaStaticJavaScriptAdapter().analyze(app, out)

    assert result["state"] == "failed"
    assert result["partial"] is True
    assert result["produced_evidence"] is False
    assert (out / "rea-result.partial.txt").is_file()
    assert not (out / "rea-result.json").exists()
    assert not (out / "rea-federated-report.v1.json").exists()


def test_artifact_correspondence_joins_only_exact_snapshot_identity():
    main_sha = hashlib.sha256(b"main source").hexdigest()
    preload_sha = hashlib.sha256(b"preload source").hexdigest()
    different_sha = hashlib.sha256(b"different bytes").hexdigest()
    snapshot = {
        "schema": "project-snapshot.v1",
        "scope": "complete",
        "files": [
            {"path": "main.js", "sha256": main_sha, "size": 11},
            {"path": "preload.js", "sha256": preload_sha, "size": 14},
        ],
    }
    project_report = {
        "inventory": {
            "files": [
                {"path": "main.js", "sha256": main_sha, "size": 11},
                {"path": "preload.js", "sha256": preload_sha, "size": 14},
            ]
        },
        "source": {
            "language_profiles": {
                "profiles": {
                    "javascript": {
                        "modules": [
                            {"path": "main.js", "sha256": main_sha, "size": 11},
                            {"path": "preload.js", "sha256": preload_sha, "size": 14},
                        ]
                    }
                }
            }
        },
    }
    rea_result = {
        "graph": {
            "nodes": [
                {
                    "node_id": "rea-main",
                    "kind": "javascript-module",
                    "identity": {"artifact_sha256": main_sha, "module_path": "main.js"},
                    "observations": [],
                },
                {
                    "node_id": "rea-wrong-hash",
                    "kind": "javascript-module",
                    "identity": {"artifact_sha256": different_sha, "module_path": "preload.js"},
                    "observations": [],
                },
                {
                    "node_id": "rea-wrong-path",
                    "kind": "javascript-module",
                    "identity": {"artifact_sha256": main_sha, "module_path": "other.js"},
                    "observations": [],
                },
            ]
        }
    }

    result = rea_static.build_artifact_correspondence(snapshot, rea_result, project_report)

    assert result["schema"] == "artifact-correspondence.v1"
    assert result["relation_semantics"] == "same_input_bytes_only"
    assert result["semantic_graph_merge"] == "not_attempted"
    assert result["summary"]["files_with_exact_engine_identity"] == 1
    main = next(row for row in result["files"] if row["path"] == "main.js")
    preload = next(row for row in result["files"] if row["path"] == "preload.js")
    assert main["aetherre"]["source_module"] is True
    assert main["rea"]["graph_node_ids"] == ["rea-main"]
    assert main["exact_identity_across_engines"] is True
    assert preload["aetherre"]["source_module"] is True
    assert preload["rea"]["graph_node_ids"] == []
    assert preload["exact_identity_across_engines"] is False


def test_artifact_correspondence_rejects_unsafe_snapshot_paths():
    snapshot = {
        "schema": "project-snapshot.v1",
        "scope": "complete",
        "files": [{"path": "../outside.js", "sha256": "a" * 64, "size": 1}],
    }

    try:
        rea_static.build_artifact_correspondence(snapshot, {"graph": {"nodes": []}}, {"inventory": {"files": []}})
    except ValueError as exc:
        assert str(exc) == "artifact_correspondence_relative_path_invalid"
    else:
        raise AssertionError("unsafe_snapshot_path_accepted")


def test_artifact_correspondence_keeps_rea_identity_conflict_unmatched():
    source = b"main source"
    source_sha = hashlib.sha256(source).hexdigest()
    conflicting_sha = hashlib.sha256(b"different identity").hexdigest()
    snapshot = {
        "schema": "project-snapshot.v1",
        "scope": "complete",
        "files": [{"path": "main.js", "sha256": source_sha, "size": len(source)}],
    }
    rea_result = {
        "graph": {
            "nodes": [
                {
                    "node_id": "rea-conflict",
                    "kind": "javascript-module",
                    "identity": {"artifact_sha256": conflicting_sha},
                    "observations": [
                        {
                            "evidence": {
                                "artifact": {"sha256": source_sha},
                                "location": {"value": {"source": "main.js"}},
                            }
                        }
                    ],
                }
            ]
        }
    }
    project_report = {
        "inventory": {"files": [{"path": "main.js", "sha256": source_sha, "size": len(source)}]},
        "source": {"language_profiles": {"profiles": {"javascript": {"modules": []}}}},
    }

    result = rea_static.build_artifact_correspondence(snapshot, rea_result, project_report)

    row = result["files"][0]
    assert row["rea"]["graph_node_ids"] == []
    assert row["exact_identity_across_engines"] is False
    mismatch = result["unmatched_rea_references"][0]
    assert mismatch["node_id"] == "rea-conflict"
    assert mismatch["path"] == "main.js"
    assert mismatch["reason"] == "identity_digest_conflict"
    assert mismatch["identity_sha256"] == conflicting_sha
    assert mismatch["observation_sha256"] == source_sha


def test_artifact_correspondence_rejects_case_colliding_snapshot_paths():
    digest = hashlib.sha256(b"same bytes").hexdigest()
    snapshot = {
        "schema": "project-snapshot.v1",
        "scope": "complete",
        "files": [
            {"path": "src/Main.js", "sha256": digest, "size": 10},
            {"path": "src/main.js", "sha256": digest, "size": 10},
        ],
    }

    try:
        rea_static.build_artifact_correspondence(
            snapshot,
            {"graph": {"nodes": []}},
            {"inventory": {"files": []}},
        )
    except ValueError as exc:
        assert str(exc) == "artifact_correspondence_snapshot_duplicate_path"
    else:
        raise AssertionError("case_colliding_snapshot_paths_accepted")


def test_artifact_correspondence_retains_inventory_size_conflict():
    source = b"four"
    digest = hashlib.sha256(source).hexdigest()
    snapshot = {
        "schema": "project-snapshot.v1",
        "scope": "complete",
        "files": [{"path": "main.js", "sha256": digest, "size": len(source)}],
    }
    project_report = {
        "inventory": {"files": [{"path": "main.js", "sha256": digest, "size": len(source) + 1}]},
        "source": {
            "language_profiles": {
                "profiles": {
                    "javascript": {
                        "modules": [{"path": "main.js", "sha256": digest, "size": len(source) + 1}]
                    }
                }
            }
        },
    }

    result = rea_static.build_artifact_correspondence(
        snapshot,
        {"graph": {"nodes": []}},
        project_report,
    )

    assert result["status"] == "partial"
    assert result["summary"]["aetherre_inventory_matches"] == 0
    assert result["summary"]["aetherre_source_modules"] == 0
    assert result["summary"]["conflicts"] == 2
    assert {item["reason"] for item in result["conflicts"]} == {
        "snapshot_identity_mismatch",
        "source_module_identity_mismatch",
    }


def test_artifact_correspondence_rejects_duplicate_rea_node_ids():
    digest = hashlib.sha256(b"main source").hexdigest()
    node = {
        "node_id": "rea-duplicate",
        "kind": "javascript-module",
        "identity": {"artifact_sha256": digest, "module_path": "main.js"},
        "observations": [],
    }
    snapshot = {
        "schema": "project-snapshot.v1",
        "scope": "complete",
        "files": [{"path": "main.js", "sha256": digest, "size": 11}],
    }

    try:
        rea_static.build_artifact_correspondence(
            snapshot,
            {"graph": {"nodes": [node, node]}},
            {"inventory": {"files": [{"path": "main.js", "sha256": digest, "size": 11}]}},
        )
    except ValueError as exc:
        assert str(exc) == "artifact_correspondence_rea_duplicate_node_id"
    else:
        raise AssertionError("duplicate_rea_node_ids_accepted")


def test_rea_static_adapter_analyzes_asar_archive_and_records_root_correspondence(tmp_path, monkeypatch):
    asar = tmp_path / "app.asar"
    asar_bytes = b"ASAR-packed-application-fixture"
    asar.write_bytes(asar_bytes)
    asar_sha = hashlib.sha256(asar_bytes).hexdigest()
    out = tmp_path / "out-asar"

    monkeypatch.setattr(rea_static, "verify_rea_worker", lambda *_args, **_kwargs: _worker_verification(tmp_path))

    def fake_asar_process(command, **_kwargs):
        target = Path(command[3])
        assert target.is_file() and target.suffix == ".asar"
        envelope = _rea_envelope(str(target))
        envelope["subject"]["format"] = "asar"
        envelope["subject"]["digest"]["sha256"] = asar_sha
        envelope["normalized_result"]["format"] = "asar"
        envelope["normalized_result"]["root_artifact_sha256"] = asar_sha
        payload = json.dumps(envelope, sort_keys=True)
        raw = payload.encode("utf-8")
        return {
            "returncode": 0,
            "stdout": payload,
            "stderr": "",
            "timed_out": False,
            "resource_exceeded": False,
            "output_limit_exceeded": False,
            "output_bytes": len(raw),
            "captured_output_bytes": len(raw),
            "capture_complete": True,
            "process_tree_contained": True,
        }

    monkeypatch.setattr(rea_static, "run_bounded", fake_asar_process)

    result = rea_static.ReaStaticJavaScriptAdapter().analyze(asar, out)

    assert result["state"] == "succeeded"
    assert result["ok"] is True
    assert result["produced_evidence"] is True
    report = json.loads((out / "rea-federated-report.v1.json").read_text(encoding="utf-8"))
    assert report["status"] == "complete"
    assert report["artifact_correspondence"]["status"] == "not_applicable_asar"
    assert report["artifact_correspondence"]["files"][0]["rea"]["root_artifact_match"] is True

