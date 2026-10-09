"""Benchmark estático com budgets e distinção honesta entre cold/warm."""

from __future__ import annotations

import json
import math
import os
import statistics
import time
from pathlib import Path
from typing import Any

from aether_re.build_audit import audit_build
from aether_re.project_inventory import inventory_project

try:
    import psutil
except ImportError:  # pragma: no cover - fallback explícito
    psutil = None  # type: ignore[assignment]


SCHEMA = "static-benchmark.v1"

_LIMITATIONS = [
    "primeira passada e cache do SO, não cold disk controlado",
    "não isola CPU/IO de outros processos",
    "benchmark mede inventário/build-audit estáticos, não adapters ou execução do alvo",
    "variação do host impede comparar números entre máquinas sem perfil fixo",
]


def _root_display(root: object) -> str:
    """Representa a raiz sem deixar uma entrada inválida gerar traceback."""
    try:
        return str(Path(root))
    except (TypeError, ValueError, OSError):
        return repr(root)


def _invalid_report(root: object, iterations: object, code: str, detail: str) -> dict[str, Any]:
    """Retorna um relatório terminal e explícito para entradas não executáveis."""
    return {
        "schema": SCHEMA,
        "status": "invalid",
        "root": _root_display(root),
        "iterations": iterations,
        "timings": [],
        "issues": [{"code": code, "detail": detail}],
        "summary": {
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
            "peak_rss_bytes": 0,
            "psutil_available": psutil is not None,
            "iterations_recorded": 0,
            "inventory_statuses": [],
            "build_statuses": [],
        },
        "limitations": list(_LIMITATIONS),
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    # nearest-rank conservador: p95 nunca es menor que o segundo maior valor
    # apenas porque a amostra é pequena.
    index = min(len(ordered) - 1, max(0, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def benchmark_static_project(root: Path, *, iterations: int = 3) -> dict[str, Any]:
    # bool é int em Python, mas nunca é uma contagem válida; rejeitar também
    # floats/strings evita que range() vaze um traceback para a CLI.
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1 or iterations > 100:
        return _invalid_report(root, iterations, "iterations_out_of_range", "integer_range=1..100")
    try:
        root = Path(root).resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        return _invalid_report(root, iterations, "root_invalid", type(exc).__name__)
    try:
        root_exists = root.is_dir()
    except (OSError, RuntimeError):
        root_exists = False
    if not root_exists:
        return _invalid_report(root, iterations, "root_missing", "directory_required")

    timings: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    inventory_statuses: list[str] = []
    build_statuses: list[str] = []
    try:
        process = psutil.Process(os.getpid()) if psutil is not None else None
    except Exception as exc:  # pragma: no cover - depende do host
        process = None
        issues.append({"code": "rss_unavailable", "detail": type(exc).__name__})
    for index in range(iterations):
        try:
            before = process.memory_info().rss if process else None
        except Exception as exc:  # pragma: no cover - depende do host
            before = None
            issues.append({"iteration": index + 1, "code": "rss_read_error", "detail": type(exc).__name__})
        started = time.perf_counter_ns()
        try:
            inventory = inventory_project(root)
        except Exception as exc:
            inventory = {"status": "invalid"}
            issues.append({"iteration": index + 1, "component": "inventory", "code": "analysis_error", "detail": type(exc).__name__})
        try:
            build = audit_build(root)
        except Exception as exc:
            build = {"status": "invalid"}
            issues.append({"iteration": index + 1, "component": "build_audit", "code": "analysis_error", "detail": type(exc).__name__})
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        try:
            after = process.memory_info().rss if process else None
        except Exception as exc:  # pragma: no cover - depende do host
            after = None
            issues.append({"iteration": index + 1, "code": "rss_read_error", "detail": type(exc).__name__})
        inventory_status = inventory.get("status") if isinstance(inventory, dict) else "invalid"
        build_status = build.get("status") if isinstance(build, dict) else "invalid"
        if not isinstance(inventory_status, str):
            inventory_status = "invalid"
            issues.append({"iteration": index + 1, "component": "inventory", "code": "invalid_result", "detail": "status_string_required"})
        if not isinstance(build_status, str):
            build_status = "invalid"
            issues.append({"iteration": index + 1, "component": "build_audit", "code": "invalid_result", "detail": "status_string_required"})
        elif build_status not in {"observed", "not_found", "partial", "invalid"}:
            issues.append({"iteration": index + 1, "component": "build_audit", "code": "invalid_result", "detail": f"unknown_status={build_status}"})
            build_status = "invalid"
        if inventory_status not in {"complete", "partial", "invalid"}:
            issues.append({"iteration": index + 1, "component": "inventory", "code": "invalid_result", "detail": f"unknown_status={inventory_status}"})
            inventory_status = "invalid"
        inventory_statuses.append(inventory_status)
        build_statuses.append(build_status)
        timings.append(
            {
                "iteration": index + 1,
                "cache_label": "first_process_pass" if index == 0 else "subsequent_os_cache_uncontrolled",
                "elapsed_ms": elapsed_ms,
                "rss_before": before,
                "rss_after": after,
                "rss_delta": after - before if before is not None and after is not None else None,
                "inventory_status": inventory_status,
                "build_status": build_status,
            }
        )
    values = [float(item["elapsed_ms"]) for item in timings]
    peak_rss = max((item["rss_after"] or 0 for item in timings), default=0)
    invalid_statuses = {"invalid"}
    partial_statuses = {"partial"}
    if issues or any(status in invalid_statuses for status in inventory_statuses + build_statuses):
        status = "invalid"
    elif any(status in partial_statuses for status in inventory_statuses + build_statuses):
        status = "partial"
    else:
        status = "complete"
    return {
        "schema": SCHEMA,
        "status": status,
        "root": str(root),
        "iterations": iterations,
        "timings": timings,
        "issues": issues,
        "summary": {
            "p50_ms": _percentile(values, 0.50),
            "p95_ms": _percentile(values, 0.95),
            "min_ms": min(values),
            "max_ms": max(values),
            "mean_ms": statistics.fmean(values),
            "peak_rss_bytes": peak_rss,
            "psutil_available": process is not None,
            "iterations_recorded": len(timings),
            "inventory_statuses": inventory_statuses,
            "build_statuses": build_statuses,
        },
        "limitations": list(_LIMITATIONS),
    }


def write_benchmark_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
