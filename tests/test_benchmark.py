import json

import aether_re.benchmark as benchmark_module
from aether_re.benchmark import benchmark_static_project, write_benchmark_report


def test_static_benchmark_records_cold_warm_labels_and_percentiles(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text("value = 1\n", encoding="utf-8")
    (root / "requirements.txt").write_text("example==1\n", encoding="utf-8")
    report = benchmark_static_project(root, iterations=3)
    assert report["schema"] == "static-benchmark.v1"
    assert report["status"] == "complete"
    assert len(report["timings"]) == 3
    assert report["timings"][0]["cache_label"] == "first_process_pass"
    assert report["timings"][1]["cache_label"] == "subsequent_os_cache_uncontrolled"
    assert report["summary"]["p95_ms"] >= report["summary"]["p50_ms"]
    out = tmp_path / "benchmark.json"
    write_benchmark_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == report["schema"]


def test_static_benchmark_rejects_unbounded_iterations(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    report = benchmark_static_project(root, iterations=101)
    assert report["status"] == "invalid"
    assert report["issues"][0]["code"] == "iterations_out_of_range"


def test_static_benchmark_rejects_bool_iterations_without_traceback(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    report = benchmark_static_project(root, iterations=True)
    assert report["status"] == "invalid"
    assert report["timings"] == []
    assert report["issues"][0]["code"] == "iterations_out_of_range"


def test_static_benchmark_rejects_missing_root_without_running_passes(tmp_path):
    missing = tmp_path / "does-not-exist"
    report = benchmark_static_project(missing, iterations=2)
    assert report["status"] == "invalid"
    assert report["timings"] == []
    assert report["issues"][0]["code"] == "root_missing"
    assert report["summary"]["iterations_recorded"] == 0


def test_static_benchmark_does_not_promote_partial_component_to_complete(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.setattr(benchmark_module, "inventory_project", lambda _: {"status": "partial"})
    monkeypatch.setattr(benchmark_module, "audit_build", lambda _: {"status": "not_found"})
    report = benchmark_static_project(root, iterations=1)
    assert report["status"] == "partial"
    assert report["summary"]["inventory_statuses"] == ["partial"]
