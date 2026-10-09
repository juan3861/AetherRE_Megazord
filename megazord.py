#!/usr/bin/env python3
"""
AetherRE MEGAZORD — CLI
Uso:
  py -3.13 megazord.py analyze CAMINHO\\para\\binario.exe
  py -3.13 megazord.py status
  py -3.13 megazord.py selftest
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
import zipfile
from pathlib import Path


def _configure_stdio() -> None:
    """Keep argparse/help and forensic reports printable on legacy Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


_configure_stdio()


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (FileNotFoundError, OSError):
        return None


def _sha256_json(value: object) -> str | None:
    try:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(payload).hexdigest()

# garantir imports locais
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aether_re import __version__, __codename__
from aether_re.cache import analysis_cache_key, verify_manifest
from aether_re.pipeline import CasePolicy, adapters_status, run_megazord, run_universal_case
from aether_re.source import analyze_python_project, write_source_report
from aether_re.c_source import analyze_c_family_project, write_c_source_report
from aether_re.build_audit import audit_build, write_build_report
from aether_re.build_link import link_build_artifact, write_build_link_report
from aether_re.repro_package import create_repro_package, restore_repro_package, verify_repro_package, write_repro_report
from aether_re.project_audit import analyze_project, write_project_audit
from aether_re.project_snapshot import create_project_snapshot, verify_project_snapshot
from aether_re.evidence_contract import load_evidence_file, validate_evidence_records, write_evidence_validation
from aether_re.custody import create_custody_receipt, verify_custody_receipt, write_custody_report
from aether_re.project_dependencies import audit_project_dependencies, write_project_dependency_report
from aether_re.trace_correlation import correlate_trace, write_trace_correlation
from aether_re.sarif import report_to_sarif, write_sarif
from aether_re.benchmark import benchmark_static_project, write_benchmark_report
from aether_re.dynamic_effects import validate_effects, write_effects_report
from aether_re.corpus_eval import evaluate_corpus_binaries, evaluate_corpus_source, write_corpus_evaluation
from aether_re.profile_comparison import compare_binary_profiles, write_profile_comparison
from aether_re.corpus import build_c_corpus_msvc, build_c_corpus_wsl, validate_corpus_builds, write_build_validation
from aether_re.correlation import correlate_source_to_binary, write_correlation_report
from aether_re.dependency_audit import audit_python_dependencies, write_dependency_report
from aether_re.risk_audit import audit_source_risks, write_risk_report
from aether_re.taint_audit import audit_python_taint
from aether_re.trace import validate_trace_document, write_trace_report
from aether_re.lab_policy import LabPolicy, preflight_dynamic_lab, validate_runtime_proof
from aether_re.differential import compare_observations, write_differential_report
from aether_re.behavioral_runner import compare_signed_behavioral_run, strict_json_loads
from aether_re.fuzz import generate_mutations, write_fuzz_report
from aether_re.metrics import calibration_metrics, evaluate_blind_holdout, write_metrics_report
from aether_re.claims import validate_claims, write_claim_report
from aether_re.doctor import diagnose_tools
from aether_re.homologation import audit_run_package, write_homologation_report
from aether_re.project_inventory import inventory_project, write_inventory_report
from aether_re.assistant import propose_hypotheses, verify_proposals, write_assistant_report
from aether_re.review_ui import write_review_html
from aether_re.symbolic import validate_symbolic_result, write_symbolic_report
from aether_re.phase_gates import evaluate_phase_gates, write_phase_gate_report
from aether_re.release_certification import certify_release
from aether_re.release_builder import ReleaseManifestBuildError, build_release_manifest
from aether_re.release_inventory import ReleaseInventoryError, create_release_inventory
from aether_re.corpus_registry import validate_corpus_registry
from aether_re.dynamic_lab_contracts import DynamicLabHandoff
from aether_re.toolchain_lock import ContractError as ToolchainContractError, load_toolchain_lock, verify_toolchain_lock
from aether_re.jar_worker import verify_jar_workers_lock
from aether_re.firmware_layout import qualify_firmware_layout
from aether_re.profile_certification import certify_static_profile
from aether_re.static_profiles import PROFILE_DECLARATIONS, detect_static_profiles
from aether_re.validation_campaign import CampaignCase, run_validation_campaign
from aether_re.documentation import audit_documentation, write_documentation_report
from aether_re.graph_store import get_node, ingest_graph, verify_graph_store, write_graph_report
from aether_re.intake import IntakeRejected, IntakeRequest, prepare_case
from aether_re.kernel_contracts import AuthorizationPolicy, ContractError, IntakeLimits


def cmd_status(_: argparse.Namespace) -> int:
    print(f"AetherRE {__codename__} v{__version__}")
    print("Adapters:")
    for s in adapters_status():
        flag = "OK" if s["available"] else "—"
        print(f"  [{flag}] {s['name']}")
    # engines nativos
    print("Engines nativos: triage, structure, strings_decode, disasm, reconstruct, elf_calls (opt-in)")
    try:
        import pefile  # noqa: F401

        print("  pefile: OK")
    except ImportError:
        print("  pefile: MISSING")
    try:
        import capstone  # noqa: F401

        print("  capstone: OK")
    except ImportError:
        print("  capstone: MISSING (disasm limitado)")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    target = Path(args.target)
    out = Path(args.out) if args.out else None
    if args.reuse_cache:
        if out is None:
            print("--reuse-cache exige --out apontando para uma execução existente", file=sys.stderr)
            return 2
        key = analysis_cache_key(target, config={"deep": not args.shallow, "use_adapters": not args.no_adapters})
        valid, errors = verify_manifest(out / "manifest.json", target, expected_cache_key=key)
        if not valid:
            print(f"Cache rejeitado: {', '.join(errors)}", file=sys.stderr)
            return 2
        report_path = out / "report.json"
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            print(f"Cache rejeitado: report_invalid:{exc.__class__.__name__}", file=sys.stderr)
            return 2
        print(f"Cache reutilizado: {out}")
        print(f"Target : {data.get('target')}")
        print(f"SHA256 : {data.get('target_sha256')}")
        print(f"Conf   : {float(data.get('overall_confidence', 0.0)):.2f}")
        print(f"Findings: {len(data.get('findings', []))}")
        return 0
    report = run_megazord(
        target,
        out_dir=out,
        use_adapters=not args.no_adapters,
        deep=not args.shallow,
        profile_id=None if getattr(args, "profile", None) == "auto" else getattr(args, "profile", None),
    )
    out_dir = report.adapter_results.get("_output_dir", "")
    print("=" * 60)
    print(f"MEGAZORD v{__version__} — análise completa")
    print("=" * 60)
    print(f"Target : {report.target}")
    print(f"SHA256 : {report.target_sha256}")
    print(f"Type   : {report.file_type} | size={report.size_bytes} | H={report.entropy:.3f}")
    print(f"Conf   : {report.overall_confidence:.2f}")
    print(f"Imports: {len(report.imports)} | Exports: {len(report.exports)} | Strings: {len(report.strings)}")
    print(f"Findings: {len(report.findings)}")
    print(f"Output : {out_dir}")
    print("-" * 60)
    for f in report.findings[:12]:
        print(f"[{f.severity}] {f.title}")
    if len(report.findings) > 12:
        print(f"... +{len(report.findings) - 12} findings (ver findings.md)")
    print("-" * 60)
    print("Ficheiros: report.json | pseudo_source.c | findings.md | strings.txt")
    return 0


def cmd_selftest(_: argparse.Namespace) -> int:
    """Gera um mini PE-like payload sintético? Melhor: analisa o próprio python.exe."""
    candidates = [
        Path(sys.executable),
        Path(r"C:\Windows\System32\notepad.exe"),
        Path(r"C:\Windows\System32\cmd.exe"),
    ]
    target = next((c for c in candidates if c.is_file()), None)
    if not target:
        print("Nenhum binário de teste encontrado")
        return 1
    print(f"Selftest target: {target}")
    # Each invocation owns a new destination.  Reusing output/selftest would
    # collide with the intake custody directory and can also inherit run.lock
    # from an interrupted run.  The UUID keeps cleanup unnecessary and scopes
    # every self-test below the repository's dedicated selftest output only.
    selftest_out = ROOT / "output" / "selftest" / f"run-{uuid.uuid4().hex}"
    args = argparse.Namespace(
        target=str(target),
        out=str(selftest_out),
        no_adapters=True,
        shallow=False,
        reuse_cache=False,
        profile=None,
    )
    return cmd_analyze(args)


def cmd_source_analyze(args: argparse.Namespace) -> int:
    root = Path(args.root)
    try:
        report = analyze_python_project(root)
    except (FileNotFoundError, NotADirectoryError, OSError, ValueError) as exc:
        report = {
            "schema": "python-source-analysis.v1",
            "root": str(root.resolve()),
            "modules": [],
            "functions": [],
            "calls": [],
            "imports": [],
            "dynamic_imports": [],
            "graph": {"schema": "source-graph.v1", "nodes": [], "edges": []},
            "errors": [{"kind": "input_invalid", "detail": type(exc).__name__}],
            "limitations": ["entrada inválida recusada antes da leitura", "nenhum módulo foi executado"],
        }
    out = Path(args.out) if args.out else (root.parent / f"{root.name}.aether_source_report.json")
    write_source_report(report, out)
    print(f"Source report: {out}")
    print(f"Modules: {len(report['modules'])} | Functions: {len(report['functions'])} | Calls: {len(report['calls'])} | Errors: {len(report['errors'])}")
    return 0 if not report["errors"] else 2


def cmd_c_source_analyze(args: argparse.Namespace) -> int:
    root = Path(args.root)
    try:
        report = analyze_c_family_project(root)
    except (FileNotFoundError, NotADirectoryError, OSError, ValueError) as exc:
        report = {
            "schema": "c-family-source-analysis.v1",
            "root": str(root.resolve()),
            "modules": [],
            "functions": [],
            "calls": [],
            "includes": [],
            "macros": [],
            "graph": {"schema": "source-graph.v1", "nodes": [], "edges": []},
            "errors": [{"kind": "input_invalid", "detail": type(exc).__name__}],
            "limitations": ["entrada inválida recusada antes da leitura", "nenhum compilador ou alvo foi executado"],
        }
    write_c_source_report(report, Path(args.out))
    print(f"C/C++ source report: {args.out} | modules={len(report['modules'])} | functions={len(report['functions'])} | calls={len(report['calls'])} | errors={len(report['errors'])}")
    return 0 if not report["errors"] else 2


def cmd_build_audit(args: argparse.Namespace) -> int:
    report = audit_build(Path(args.root), max_files=args.max_files, max_file_bytes=args.max_file_bytes)
    write_build_report(report, Path(args.out))
    print(f"Build audit: {args.out} | status={report['status']} | build_files={len(report['files'])} | systems={','.join(report.get('build_systems', [])) or 'none'}")
    return 0 if report["status"] in {"observed", "not_found"} else 2


def cmd_build_link(args: argparse.Namespace) -> int:
    try:
        build_report = json.loads(Path(args.build_report).read_text(encoding="utf-8"))
        binary_report = json.loads(Path(args.binary_report).read_text(encoding="utf-8")) if args.binary_report else None
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {"schema": "build-artifact-link.v1", "status": "invalid", "executed": False, "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}]}
        write_build_link_report(report, Path(args.out))
        print(f"Build link: {args.out} | status=invalid")
        return 2
    report = link_build_artifact(build_report, Path(args.binary), binary_report=binary_report)
    write_build_link_report(report, Path(args.out))
    print(f"Build link: {args.out} | status={report['status']} | matches={len(report.get('matches', []))}")
    return 0 if report["status"] in {"linked", "unmatched"} else 2


def cmd_repro_pack(args: argparse.Namespace) -> int:
    report = create_repro_package(Path(args.run_dir), Path(args.out), require_homologation=not args.allow_partial)
    write_repro_report(report, Path(args.report) if args.report else Path(str(args.out) + ".json"))
    print(f"Repro package: {args.out} | status={report['status']} | files={report.get('file_count', 0)}")
    return 0 if report["status"] == "created" else 2


def cmd_repro_verify(args: argparse.Namespace) -> int:
    report = verify_repro_package(Path(args.package))
    if args.out:
        write_repro_report(report, Path(args.out))
    print(f"Repro verify: {args.package} | status={report['status']} | issues={len(report['issues'])}")
    return 0 if report["status"] == "pass" else 2


def cmd_repro_restore(args: argparse.Namespace) -> int:
    report = restore_repro_package(Path(args.package), Path(args.destination), max_total_bytes=args.max_total_bytes)
    if args.out:
        write_repro_report(report, Path(args.out))
    print(f"Repro restore: {args.destination} | status={report['status']} | files={len(report.get('files', []))}")
    return 0 if report.get("status") == "restored" else 2


def cmd_project_audit(args: argparse.Namespace) -> int:
    report = analyze_project(Path(args.root))
    write_project_audit(report, Path(args.out))
    summary = report.get("summary", {})
    print(f"Project audit: {args.out} | status={report['status']} | languages={','.join(summary.get('languages', [])) or 'none'} | modules={summary.get('modules', 0)} | functions={summary.get('functions', 0)}")
    return 0 if report["status"] == "complete" else 2


def cmd_project_snapshot(args: argparse.Namespace) -> int:
    try:
        report = create_project_snapshot(
            Path(args.root), Path(args.destination), max_files=args.max_files,
            max_bytes=args.max_bytes, max_file_bytes=args.max_file_bytes,
            immutable=getattr(args, "immutable", False),
        )
    except (OSError, ValueError) as exc:
        report = {"schema": "project-snapshot.v1", "status": "rejected", "destination": str(args.destination), "issues": [{"code": str(exc) if isinstance(exc, ValueError) else "snapshot_io_error", "detail": type(exc).__name__}]}
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Project snapshot: {args.destination} | status={report['status']} | scope={report.get('scope', 'none')} | files={report.get('file_count', 0)}")
    return 0 if report["status"] == "created" and report.get("scope") == "complete" else 2


def _parse_custody_artifacts(values: list[str]) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for value in values:
        if not isinstance(value, str) or "=" not in value:
            raise ValueError("artifact_requires_name_equals_path")
        name, raw_path = value.split("=", 1)
        if not name or not raw_path or name in artifacts:
            raise ValueError("artifact_name_invalid")
        artifacts[name] = Path(raw_path)
    if not artifacts:
        raise ValueError("artifacts_required")
    return artifacts


def cmd_custody_create(args: argparse.Namespace) -> int:
    try:
        metadata = json.loads(args.metadata) if args.metadata else None
        artifacts = _parse_custody_artifacts(args.artifact)
        report = create_custody_receipt(artifacts, Path(args.out), metadata=metadata, previous_receipt=Path(args.previous) if args.previous else None, immutable=args.immutable)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        report = {"schema": "custody-receipt.v1", "status": "invalid", "receipt": str(args.out), "issues": [{"code": str(exc) if isinstance(exc, ValueError) else "custody_input_invalid", "detail": type(exc).__name__}]}
    write_custody_report(report, Path(args.report) if args.report else Path(str(args.out) + ".json"))
    print(f"Custody receipt: {args.out} | status={report['status']} | artifacts={report.get('artifact_count', 0)}")
    return 0 if report.get("status") == "created" else 2


def cmd_custody_verify(args: argparse.Namespace) -> int:
    report = verify_custody_receipt(Path(args.receipt), require_sealed=args.require_sealed)
    if args.out:
        write_custody_report(report, Path(args.out))
    print(f"Custody verify: {args.receipt} | status={report['status']} | issues={len(report.get('issues', []))}")
    return 0 if report.get("status") == "pass" else 2


def cmd_project_snapshot_verify(args: argparse.Namespace) -> int:
    report = verify_project_snapshot(
        Path(args.destination), max_total_bytes=args.max_total_bytes,
        expected_manifest_sha256=args.expected_manifest_sha256,
        require_sealed=getattr(args, "require_sealed", False),
    )
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Project snapshot verify: {args.destination} | status={report['status']} | scope={report.get('scope', 'none')} | issues={len(report['issues'])}")
    return 0 if report["status"] == "pass" else 2


def cmd_evidence_validate(args: argparse.Namespace) -> int:
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8")) if args.manifest else None
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = validate_evidence_records(None, strict=args.strict)  # type: ignore[arg-type]
        report["errors"] = [{"evidence_id": "<input>", "code": "input_unreadable", "detail": type(exc).__name__}]
        report["status"] = "invalid"
    else:
        records = data.get("evidence", data) if isinstance(data, dict) else data
        report = validate_evidence_records(records, manifest=manifest, strict=args.strict)
    write_evidence_validation(report, Path(args.out))
    print(f"Evidence validation: {args.out} | status={report['status']} | valid={report['valid_count']} | invalid={report['invalid_count']}")
    return 0 if report["status"] == "valid" else 2


def cmd_project_dependencies(args: argparse.Namespace) -> int:
    report = audit_project_dependencies(Path(args.root))
    write_project_dependency_report(report, Path(args.out))
    print(f"Project dependencies: {args.out} | status={report['status']} | declared={report['summary']['declared']} | observed={report['summary']['observed']}")
    return 0 if report["status"] in {"observed", "not_found"} else 2


def cmd_trace_correlate(args: argparse.Namespace) -> int:
    try:
        trace = json.loads(Path(args.input).read_text(encoding="utf-8"))
        source = json.loads(Path(args.source_report).read_text(encoding="utf-8")) if args.source_report else None
        binary = json.loads(Path(args.binary_report).read_text(encoding="utf-8")) if args.binary_report else None
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = correlate_trace(None)  # type: ignore[arg-type]
        report["issues"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["status"] = "invalid"
    else:
        if isinstance(trace, list):
            trace = {"schema": "dynamic-trace.v1", "status": "complete", "events": trace}
        report = correlate_trace(trace, source_report=source, binary_report=binary)
    write_trace_correlation(report, Path(args.out))
    print(f"Trace correlation: {args.out} | status={report['status']} | events={report.get('summary', {}).get('events', 0)} | source_matched={report.get('summary', {}).get('source_matched', 0)} | binary_matched={report.get('summary', {}).get('binary_matched', 0)}")
    return 0 if report["status"] == "complete" and not report.get("issues") else 2


def cmd_sarif(args: argparse.Namespace) -> int:
    try:
        report = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {"errors": [{"code": "input_unreadable", "detail": type(exc).__name__}]}
    if not isinstance(report, dict):
        report = {"errors": [{"code": "input_must_be_object"}]}
    write_sarif(report, Path(args.out), tool_version=__version__)
    sarif = report_to_sarif(report, tool_version=__version__)
    result_count = sum(len(run.get("results", [])) for run in sarif["runs"])
    errors = sum(len(run.get("properties", {}).get("errors", [])) for run in sarif["runs"])
    print(f"SARIF: {args.out} | results={result_count} | errors={errors}")
    return 0 if errors == 0 else 2


def cmd_review_html(args: argparse.Namespace) -> int:
    try:
        report = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {"schema": "forensic-review-html.v1", "status": "invalid", "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}]}
    if not isinstance(report, dict):
        report = {"schema": "forensic-review-html.v1", "status": "invalid", "errors": [{"code": "input_must_be_object"}]}
    write_review_html(report, Path(args.out), title=args.title)
    print(f"Forensic review HTML: {args.out} | status={report.get('status', 'unknown')}")
    return 0 if report.get("status") in {"complete", "pass", "verified", "partial"} and not report.get("errors") else 2


def cmd_benchmark_static(args: argparse.Namespace) -> int:
    report = benchmark_static_project(Path(args.root), iterations=args.iterations)
    write_benchmark_report(report, Path(args.out))
    summary = report.get("summary", {})
    print(f"Static benchmark: {args.out} | status={report['status']} | p50_ms={summary.get('p50_ms', 0):.3f} | p95_ms={summary.get('p95_ms', 0):.3f} | peak_rss={summary.get('peak_rss_bytes', 0)}")
    return 0 if report["status"] == "complete" else 2


def cmd_effects_validate(args: argparse.Namespace) -> int:
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = validate_effects(None, allowed_roots=[], max_events=args.max_events)  # type: ignore[arg-type]
        report["issues"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["summary"] = {"received": 0, "accepted": 0, "issues": 1}
    else:
        events = data.get("events", data) if isinstance(data, dict) else data
        report = validate_effects(events, allowed_roots=[Path(item) for item in args.allowed_root], network_enabled=args.network_enabled, writable_project=args.writable_project, max_events=args.max_events)
    write_effects_report(report, Path(args.out))
    print(f"Effects validation: {args.out} | status={report['status']} | accepted={report['summary']['accepted']} | issues={report['summary']['issues']}")
    return 0 if report["status"] == "valid" else 2


def cmd_corpus_evaluate(args: argparse.Namespace) -> int:
    report = evaluate_corpus_source(Path(args.manifest))
    write_corpus_evaluation(report, Path(args.out))
    print(f"Corpus source evaluation: {args.out} | status={report['status']} | projects={len(report.get('projects', []))} | errors={len(report.get('errors', []))}")
    return 0 if report["status"] == "complete" else 2


def cmd_corpus_evaluate_binaries(args: argparse.Namespace) -> int:
    report = evaluate_corpus_binaries(
        Path(args.manifest),
        Path(args.build_report),
        measure_relations=args.measure_direct_calls,
        dia_helper=Path(args.dia_helper) if args.dia_helper else None,
        dia_dll=Path(args.dia_dll) if args.dia_dll else None,
        pdb_timeout=args.pdb_timeout,
        pdb_max_symbols=args.pdb_max_symbols,
    )
    write_corpus_evaluation(report, Path(args.out))
    print(f"Corpus binary evaluation: {args.out} | status={report['status']} | projects={len(report.get('projects', []))}")
    return 0 if report["status"] == "complete" else 2


def cmd_compare_binary_profiles(args: argparse.Namespace) -> int:
    try:
        baseline_bytes = Path(args.baseline).read_bytes()
        candidate_bytes = Path(args.candidate).read_bytes()
        if len(baseline_bytes) > 64 * 1024 * 1024 or len(candidate_bytes) > 64 * 1024 * 1024:
            raise ValueError("evaluation_file_too_large")
        baseline = json.loads(baseline_bytes)
        candidate = json.loads(candidate_bytes)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        report = {"schema": "binary-profile-comparison.v1", "status": "invalid", "projects": [], "summary": {}, "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}], "limitations": ["nenhum binário foi executado"]}
    else:
        report = compare_binary_profiles(baseline, candidate)
        report["inputs"] = {"baseline_sha256": hashlib.sha256(baseline_bytes).hexdigest(), "candidate_sha256": hashlib.sha256(candidate_bytes).hexdigest()}
    write_profile_comparison(report, Path(args.out))
    print(f"Binary profile comparison: {args.out} | status={report['status']} | projects={len(report.get('projects', []))}")
    return 0 if report["status"] == "complete" else 2


def cmd_corpus_validate(args: argparse.Namespace) -> int:
    report = validate_corpus_builds(Path(args.manifest))
    out = Path(args.out) if args.out else Path(args.manifest).with_name("build_validation.json")
    write_build_validation(report, out)
    counts: dict[str, int] = {}
    for item in report["results"]:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    print(f"Corpus build validation: {out} | status={report.get('status', 'unknown')} | " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0 if report.get("status") == "complete" else 2


def cmd_correlate(args: argparse.Namespace) -> int:
    try:
        source = json.loads(Path(args.source_report).read_text(encoding="utf-8"))
        binary_data = json.loads(Path(args.binary_report).read_text(encoding="utf-8"))
        build = json.loads(Path(args.build_report).read_text(encoding="utf-8")) if args.build_report else None
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = correlate_source_to_binary(None, None)  # type: ignore[arg-type]
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
    else:
        if not isinstance(source, dict) or not isinstance(binary_data, dict):
            report = correlate_source_to_binary(None, None)  # type: ignore[arg-type]
            report["errors"] = [{"code": "input_shape_invalid", "detail": "source_and_binary_reports_must_be_objects"}]
        else:
            binary = binary_data.get("merged_functions") or binary_data.get("functions") or binary_data.get("symbols", [])
            report = correlate_source_to_binary(source.get("functions", []), binary, build_report=build)
    write_correlation_report(report, Path(args.out))
    print(f"Correlation report: {args.out} | {report['summary']}")
    return 0 if report.get("status") in {"complete", "insufficient_data"} and not report.get("errors") else 2


def cmd_dependencies_audit(args: argparse.Namespace) -> int:
    report = audit_python_dependencies(Path(args.root))
    write_dependency_report(report, Path(args.out))
    print(f"Dependency audit: {args.out} | status={report.get('status')} | {report.get('summary', {})}")
    return 0 if report.get("status") in {"complete", "partial"} else 2


def cmd_risk_audit(args: argparse.Namespace) -> int:
    try:
        source = json.loads(Path(args.source_report).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = audit_source_risks(None)  # type: ignore[arg-type]
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["status"] = "invalid"
    else:
        report = audit_source_risks(source)
    if args.project_root:
        taint = audit_python_taint(Path(args.project_root))
        report["taint"] = taint
        report["indicators"].extend(taint["flows"])
        report["summary"]["total"] = len(report["indicators"])
        if taint.get("status") == "invalid":
            report["status"] = "invalid"
            report["errors"] = list(report.get("errors", [])) + [{"code": "taint_audit_invalid", "detail": taint.get("errors", [])}]
        elif taint.get("status") == "partial" and report.get("status") == "complete":
            report["status"] = "partial"
    write_risk_report(report, Path(args.out))
    print(f"Risk audit: {args.out} | {report['summary']}")
    return 0 if report.get("status") in {"complete", "partial"} else 2


def cmd_trace_validate(args: argparse.Namespace) -> int:
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = validate_trace_document(None)  # type: ignore[arg-type]
        report["issues"] = [{"kind": "input_unreadable", "detail": type(exc).__name__}]
        report["summary"] = {"received": 0, "accepted": 0, "issues": 1}
    else:
        events = data.get("events", data) if isinstance(data, dict) else data
        report = validate_trace_document(data, max_events=getattr(args, "max_events", 100000))
    write_trace_report(report, Path(args.out))
    print(f"Trace validation: {args.out} | {report['summary']} | status={report['status']}")
    return 0 if report["status"] == "complete" else 2


def cmd_corpus_build_native(args: argparse.Namespace) -> int:
    report = build_c_corpus_wsl(Path(args.manifest), Path(args.out), timeout=args.timeout, memory_limit_mb=args.memory_mb, opt_level=args.opt_level, debug=not args.no_debug, strip=args.strip)
    write_build_validation(report, Path(args.report) if args.report else Path(args.out) / "build_report.json")
    print(f"Native corpus build: {args.out} | status={report['status']} | results={len(report.get('results', []))}")
    return 0 if report["status"] == "complete" else 2



def cmd_corpus_build_msvc(args: argparse.Namespace) -> int:
    report = build_c_corpus_msvc(
        Path(args.manifest),
        Path(args.out),
        compiler_path=Path(args.compiler),
        vcvarsall_path=Path(args.vcvarsall),
        support_dir=Path(args.support_dir),
        timeout=args.timeout,
        memory_limit_mb=args.memory_mb,
        opt_level=args.opt_level,
        debug=not args.no_debug,
        allow_external_authorized=args.allow_external_authorized,
    )
    write_build_validation(report, Path(args.report) if args.report else Path(args.out) / "build_report.json")
    print(f"MSVC corpus build: {args.out} | status={report['status']} | results={len(report.get('results', []))}")
    return 0 if report["status"] == "complete" else 2

def cmd_lab_preflight(args: argparse.Namespace) -> int:
    policy = LabPolicy(
        authorized=args.authorized,
        isolation=args.isolation,
        network_enabled=args.network,
        writable_project_mount=args.writable_mount,
        host_execution=args.host_execution,
        snapshot_id=getattr(args, "snapshot_id", None),
        rollback_enabled=getattr(args, "rollback", False),
        collector_configured=getattr(args, "collector_configured", False),
        timeout_s=getattr(args, "timeout_s", 0),
        memory_limit_mb=getattr(args, "memory_mb", 0),
    )
    report = preflight_dynamic_lab(
        policy,
        require_runtime_proof=getattr(args, "runtime_proof", False),
    )
    proof_path = getattr(args, "proof", None)
    if proof_path:
        try:
            proof_data = json.loads(Path(proof_path).read_text(encoding="utf-8"))
            proof_report = validate_runtime_proof(proof_data, policy=policy)
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            proof_report = validate_runtime_proof(None)  # type: ignore[arg-type]
            proof_report["errors"] = [{"code": "proof_unreadable", "detail": type(exc).__name__}]
            proof_report["status"] = "invalid"
        report["runtime_proof"] = proof_report
        if proof_report.get("status") != "verified":
            report["errors"].append("runtime_proof_not_verified")
            report["status"] = "refused"
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["status"] == "ready" else 2


def cmd_differential_compare(args: argparse.Namespace) -> int:
    try:
        original = json.loads(Path(args.original).read_text(encoding="utf-8"))
        reconstructed = json.loads(Path(args.reconstructed).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = compare_observations(None, None)  # type: ignore[arg-type]
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
    else:
        original_events = original.get("observations", original) if isinstance(original, dict) else original
        reconstructed_events = reconstructed.get("observations", reconstructed) if isinstance(reconstructed, dict) else reconstructed
        report = compare_observations(original_events, reconstructed_events, max_observations=getattr(args, "max_observations", 100000))
    write_differential_report(report, Path(args.out))
    print(f"Differential report: {args.out} | {report['summary']} | status={report['status']}")
    return 0 if report["status"] == "equivalent_on_observations" else 2

def cmd_behavior_compare(args: argparse.Namespace) -> int:
    """Compare only guest observations whose handoff and rows verify against a trust map."""
    try:
        document = strict_json_loads(Path(args.input).read_text(encoding="utf-8"))
        trust_map = strict_json_loads(Path(args.trust_map).read_text(encoding="utf-8")) if args.trust_map else None
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {"schema": "behavioral-comparison.v1", "status": "invalid", "summary": {}, "mismatches": [], "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}], "limitations": ["somente observações assinadas e verificadas são comparadas"]}
    else:
        report = compare_signed_behavioral_run(document, trust_map)
    write_differential_report(report, Path(args.out))
    print(f"Behavior comparison: {args.out} | {report.get('summary', {})} | status={report.get('status')}")
    return 0 if report.get("status") in {"equivalent_on_observations", "counterexamples_found"} and not report.get("errors") else 2


def cmd_fuzz_seeds(args: argparse.Namespace) -> int:
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {"schema": "fuzz-seed-corpus.v1", "status": "invalid", "mutations": [], "summary": {"seeds": 0, "mutations": 0}, "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}], "executed_targets": False, "limitations": ["entrada rejeitada antes de gerar mutações", "não executa alvo"]}
        write_fuzz_report(report, Path(args.out))
        print(f"Fuzz seeds: {args.out} | status=invalid | error=input_unreadable")
        return 2
    if isinstance(data, dict):
        raw_seeds = data.get("seeds")
    elif isinstance(data, list):
        raw_seeds = data
    else:
        raw_seeds = None
    if not isinstance(raw_seeds, list):
        report = {"schema": "fuzz-seed-corpus.v1", "status": "invalid", "mutations": [], "summary": {"seeds": 0, "mutations": 0}, "errors": [{"code": "input_shape_invalid", "detail": "JSON object with seeds list or seed list required"}], "executed_targets": False, "limitations": ["entrada rejeitada antes de gerar mutações", "não executa alvo"]}
        write_fuzz_report(report, Path(args.out))
        print(f"Fuzz seeds: {args.out} | status=invalid | error=input_shape_invalid")
        return 2
    seeds: list[bytes] = []
    invalid_seeds: list[dict[str, Any]] = []
    for index, item in enumerate(raw_seeds if isinstance(raw_seeds, list) else []):
        if not isinstance(item, str):
            invalid_seeds.append({"index": index, "reason": "seed_hex_string_required"})
            continue
        try:
            seeds.append(bytes.fromhex(item))
        except ValueError:
            invalid_seeds.append({"index": index, "reason": "invalid_hex"})
    if invalid_seeds:
        report = {"schema": "fuzz-seed-corpus.v1", "status": "invalid", "mutations": [], "summary": {"seeds": len(seeds), "mutations": 0, "invalid_seeds": len(invalid_seeds)}, "invalid_seeds": invalid_seeds, "executed_targets": False, "limitations": ["entrada rejeitada antes de gerar mutações", "não executa alvo"]}
        write_fuzz_report(report, Path(args.out))
        print(f"Fuzz seeds: {args.out} | status=invalid | invalid_seeds={len(invalid_seeds)}")
        return 2
    try:
        mutations = generate_mutations(seeds, budget=args.budget, max_size=args.max_size)
    except ValueError as exc:
        report = {"schema": "fuzz-seed-corpus.v1", "status": "invalid", "mutations": [], "summary": {"seeds": len(seeds), "mutations": 0}, "errors": [{"code": str(exc)}], "executed_targets": False, "limitations": ["configuração rejeitada antes de gerar mutações", "não executa alvo"]}
        write_fuzz_report(report, Path(args.out))
        print(f"Fuzz seeds: {args.out} | status=invalid | error={exc}")
        return 2
    report = {"schema": "fuzz-seed-corpus.v1", "status": "generated", "mutations": mutations, "summary": {"seeds": len(seeds), "mutations": len(mutations)}, "config": {"budget": args.budget, "max_size": args.max_size}, "executed_targets": False, "limitations": ["gera entradas, não executa alvo", "cobertura e oráculo exigem harness isolado", "não é prova de ausência de bugs"]}
    write_fuzz_report(report, Path(args.out))
    print(f"Fuzz seeds: {args.out} | status=generated | {report['summary']}")
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {"schema": "calibration-report.v1", "sample_count": 0, "metrics": {}, "bins": [], "status": "invalid", "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}]}
    else:
        if isinstance(data, dict):
            rows = data.get("predictions", data.get("rows"))
        else:
            rows = data
        try:
            report = calibration_metrics(rows, bins=args.bins, group_by=args.group_by)
        except (TypeError, ValueError) as exc:
            report = {"schema": "calibration-report.v1", "sample_count": len(rows) if isinstance(rows, list) else 0, "metrics": {}, "bins": [], "status": "invalid", "errors": [{"code": str(exc)}]}
    write_metrics_report(report, Path(args.out))
    print(f"Metrics: {args.out} | n={report['sample_count']} | status={report['status']}")
    return 0 if report["status"] == "measured" else 2


def cmd_metrics_holdout(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    input_hash = _sha256_file(input_path)
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = evaluate_blind_holdout(None, calibration_frozen=False)  # type: ignore[arg-type]
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["summary"] = {"received": 0, "accepted": 0}
    else:
        if isinstance(data, dict):
            rows = data.get("predictions", data.get("rows", data))
        else:
            rows = data
        report = evaluate_blind_holdout(
            rows, bins=args.bins, calibration_frozen=args.calibration_frozen,
            minimum_samples=getattr(args, "minimum_samples", 0),
            minimum_families=getattr(args, "minimum_families", 0),
        )
        canonical_predictions_hash = _sha256_json(rows)
        declared_hash = data.get("predictions_sha256") if isinstance(data, dict) else None
        report["input_provenance"] = {"path": str(input_path.resolve()), "sha256": input_hash, "predictions_sha256": canonical_predictions_hash, "declared_predictions_sha256": declared_hash, "hash_match": declared_hash is None or declared_hash == canonical_predictions_hash}
        if declared_hash is not None and (not isinstance(declared_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", declared_hash)):
            report["input_provenance"]["hash_match"] = False
            report["errors"] = list(report.get("errors", [])) + [{"code": "predictions_hash_invalid"}]
            report["status"] = "invalid"
        elif declared_hash is not None and declared_hash != canonical_predictions_hash:
            report["errors"] = list(report.get("errors", [])) + [{"code": "predictions_hash_mismatch"}]
            report["status"] = "invalid"
    if "input_provenance" not in report:
        report["input_provenance"] = {"path": str(input_path), "sha256": input_hash, "predictions_sha256": None, "declared_predictions_sha256": None, "hash_match": input_hash is not None}
    write_metrics_report(report, Path(args.out))
    print(f"Blind holdout: {args.out} | status={report['status']} | accepted={report.get('summary', {}).get('accepted', 0)}")
    return 0 if report["status"] == "measured" else 2


def cmd_claims_validate(args: argparse.Namespace) -> int:
    try:
        claims_data = json.loads(Path(args.claims).read_text(encoding="utf-8"))
        evidence_data = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8")) if args.manifest else None
        profile_scope = json.loads(Path(args.profile_scope).read_text(encoding="utf-8")) if getattr(args, "profile_scope", None) else None
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = validate_claims(None, None, strict_evidence=args.strict_evidence)  # type: ignore[arg-type]
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["status"] = "invalid"
    else:
        claims = claims_data.get("claims", claims_data) if isinstance(claims_data, dict) else claims_data
        evidence = evidence_data.get("evidence", evidence_data) if isinstance(evidence_data, dict) else evidence_data
        report = validate_claims(
            claims, evidence, strict_evidence=args.strict_evidence,
            evidence_manifest=manifest, profile_scope=profile_scope,
        )
    write_claim_report(report, Path(args.out))
    print(f"Claims validation: {args.out} | {report['summary']}")
    return 0 if report.get("status") == "complete" and report["summary"]["unsupported"] == 0 else 2


def cmd_assist_propose(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = propose_hypotheses(None, strict_evidence=args.strict_evidence)  # type: ignore[arg-type]
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["status"] = "invalid"
    else:
        evidence = data.get("evidence", data.get("records", data)) if isinstance(data, dict) else data
        report = propose_hypotheses(evidence, question=args.question, max_hypotheses=args.max_hypotheses, strict_evidence=args.strict_evidence)
    write_assistant_report(report, Path(args.out))
    print(f"Forensic assist: {args.out} | status={report['status']} | proposals={len(report.get('proposals', []))}")
    return 0 if report.get("status") == "complete" else 2


def cmd_assist_verify(args: argparse.Namespace) -> int:
    try:
        proposals_data = json.loads(Path(args.proposals).read_text(encoding="utf-8"))
        evidence_data = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = verify_proposals(None, None, strict_evidence=args.strict_evidence)  # type: ignore[arg-type]
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["status"] = "invalid"
    else:
        proposals = proposals_data.get("proposals", proposals_data) if isinstance(proposals_data, dict) else proposals_data
        evidence = evidence_data.get("evidence", evidence_data.get("records", evidence_data)) if isinstance(evidence_data, dict) else evidence_data
        report = verify_proposals(proposals, evidence, strict_evidence=args.strict_evidence)
    write_assistant_report(report, Path(args.out))
    print(f"Forensic assist verify: {args.out} | status={report['status']} | proposals={len(report.get('results', []))}")
    return 0 if report.get("status") == "complete" else 2


def cmd_symbolic_validate(args: argparse.Namespace) -> int:
    """Validate an externally-produced symbolic exploration artifact.

    This command is deliberately a validator only: it never imports a solver,
    executes a target, or treats UNSAT as a universal proof.
    """
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = validate_symbolic_result(None)  # type: ignore[arg-type]
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["status"] = "invalid"
    else:
        report = validate_symbolic_result(data, max_paths=args.max_paths)
    write_symbolic_report(report, Path(args.out))
    print(f"Symbolic validation: {args.out} | status={report['status']} | conclusion={report.get('conclusion', 'not_proven')}")
    return 0 if report.get("status") == "complete" else 2


def cmd_phase_gates(args: argparse.Namespace) -> int:
    """Evaluate F00--F12 declarations and materialized evidence only."""
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = evaluate_phase_gates(None, root=Path(args.root) if args.root else None)
        report["errors"] = [{"code": "input_unreadable", "detail": type(exc).__name__}]
        report["status"] = "invalid"
        report["gate_passed"] = False
    else:
        report = evaluate_phase_gates(data, root=Path(args.root) if args.root else None, max_evidence=args.max_evidence)
    write_phase_gate_report(report, Path(args.out))
    summary = report.get("summary", {})
    print(f"Phase gates: {args.out} | status={report['status']} | gate_passed={report.get('gate_passed', False)} | quitada={summary.get('quitada', 0)}")
    return 0 if report.get("gate_passed") is True else 2


def cmd_release_certify(args: argparse.Namespace) -> int:
    """Certify a materialized release against an external review trust domain."""
    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        review = json.loads(Path(args.review).read_text(encoding="utf-8"))
        trust_map = json.loads(Path(args.trust_map).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {
            "schema": "release-certification.v1",
            "status": "PARCIALMENTE_QUITADA",
            "certified": False,
            "errors": [{"code": "certification_input_unreadable", "detail": type(exc).__name__}],
        }
    else:
        report = certify_release(manifest, review, trust_map, release_root=Path(args.release_root))
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Release certification: {args.out} | status={report['status']} | certified={report['certified']}")
    return 0 if report.get("certified") is True else 3


def cmd_lab_qualify(args: argparse.Namespace) -> int:
    """Validate a supplied real-VM handoff; never launch a VM or sample."""
    try:
        document = json.loads(Path(args.input).read_text(encoding="utf-8"))
        handoff = DynamicLabHandoff.from_dict(document)
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, ContractError) as exc:
        report = {"schema": "vm-qualification-report.v1", "qualified": False, "structurally_valid": False, "execution": False,
                  "errors": [{"code": "handoff_invalid", "detail": type(exc).__name__}]}
    else:
        report = {"schema": "vm-qualification-report.v1", "qualified": False, "structurally_valid": True, "execution": False,
                  "run_id": handoff.run_lease.run_id, "vm_provider": handoff.run_lease.vm_provider,
                  "guest_id": handoff.run_lease.guest_id, "snapshot_id": handoff.run_lease.snapshot_id,
                  "errors": [{"code": "external_signed_vm_attestation_required"}],
                  "limitations": ["validation only; no VM, guest, sample, or hypervisor command was executed"]}
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Lab qualification: {args.out} | qualified={report['qualified']} | execution=False")
    return 0 if report["qualified"] else 3


def cmd_toolchain_verify(args: argparse.Namespace) -> int:
    """Rehash a locked toolchain without launching any external worker."""
    try:
        report = verify_toolchain_lock(load_toolchain_lock(args.lock))
        if args.jar_lock:
            java_report = verify_jar_workers_lock(args.jar_lock)
            report['jar_workers'] = java_report.get('workers', [])
            report['jar_workers_verified'] = java_report['verified']
            if java_report.get('errors'):
                report.setdefault('errors', []).extend(java_report['errors'])
            report['verified'] = bool(report['verified'] and java_report['verified'])
    except ToolchainContractError as exc:
        report = {"schema": "toolchain-verification.v1", "verified": False, "tools": [],
                  "errors": [{"code": str(exc)}]}
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Toolchain verification: {args.out} | verified={report['verified']}")
    return 0 if report["verified"] else 3


def cmd_profile_certify(args: argparse.Namespace) -> int:
    """Recalculate a bounded static-profile certificate from supplied evidence.

    This command accepts only materialized JSON.  It neither runs a target nor
    trusts a producer's status field in place of the certificate denominator.
    """
    try:
        inputs = {
            name: json.loads(Path(path).read_text(encoding="utf-8"))
            for name, path in {
                "profile_scope": args.profile_scope,
                "corpus": args.corpus,
                "workers": args.workers,
                "evaluation": args.evaluation,
                "baseline": args.baseline,
            }.items()
        }
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {
            "schema": "static-profile-certificate.v1",
            "profile_id": "unknown",
            "status": "NAO_COMPROVADA",
            "errors": [{"code": "certification_input_unreadable", "detail": type(exc).__name__}],
            "limitations": ["certificate was not evaluated because one or more input documents are unreadable"],
        }
    else:
        report = certify_static_profile(
            **inputs,
            evidence_root=args.evidence_root,
            external_trust_map=args.trust_map,
        )
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Profile certificate: {args.out} | profile={report.get('profile_id')} | status={report['status']}")
    return 0 if report.get("status") == "QUITADA" else 3


def cmd_profile_probe(args: argparse.Namespace) -> int:
    """Identify a static profile and print its declared capability envelope.

    Detection is deliberately not a certificate: unknown and ambiguous inputs
    receive a typed non-zero result rather than a guessed backend.
    """
    target = Path(args.input)
    try:
        matches = detect_static_profiles(target)
    except (OSError, ValueError) as exc:
        report = {"schema": "profile-probe.v1", "status": "unrecognized", "input": str(target),
                  "matches": [], "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}]}
    else:
        rows = []
        for match in matches:
            declaration = PROFILE_DECLARATIONS[match.profile_id]
            rows.append({
                "profile_id": match.profile_id, "confidence": match.confidence,
                "reasons": list(match.reasons), "candidates": list(match.candidates),
                "capability_envelope": {
                    "formats": list(declaration.formats), "address_spaces": list(declaration.address_spaces),
                    "backends": list(declaration.backend_names), "static_only": declaration.static_only,
                },
            })
        status = "identified" if len(rows) == 1 else ("ambiguous" if rows else "unrecognized")
        report = {"schema": "profile-probe.v1", "status": status, "input": str(target), "matches": rows,
                  "limitations": ["profile detection is not a worker execution or a profile certificate"]}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        output = Path(args.out); output.parent.mkdir(parents=True, exist_ok=True); output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")
    return 0 if report["status"] == "identified" else 2


def cmd_lab_export_handoff(args: argparse.Namespace) -> int:
    """Export a data-only real-VM handoff template; never fabricate attestation."""
    output = Path(args.out)
    template = {
        "schema": "dynamic-lab-handoff-template.v1", "status": "NOT_EXECUTED",
        "required_contracts": ["run-lease.v1", "vm-qualification.v1", "dynamic-trace.v1", "rollback-attestation.v1"],
        "requirements": ["real VM only", "known checkpoint", "isolated network", "disposable disk", "lease nonce", "signed evidence", "verified rollback"],
        "forbidden_substitutes": ["WSL", "container", "host-direct"],
        "limitations": ["template is not a dynamic-lab-handoff.v1", "template cannot qualify a VM or prove execution/rollback"],
    }
    readme = ("AetherRE dynamic-lab handoff\n\nThis package is a template only. Do not present it as VM evidence.\n"
              "A real lab must return a linked dynamic-lab-handoff.v1 with four distinct signed evidence IDs.\n"
              "Validate it with: megazord lab-qualify --input <handoff.json> --out <report.json>\n")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise FileExistsError("handoff_output_exists")
        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("README.txt", readme)
            archive.writestr("handoff-template.json", json.dumps(template, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
        report = {"schema": "dynamic-lab-handoff-export.v1", "status": "template_exported", "output": str(output), "sha256": _sha256_file(output),
                  "execution": False, "qualified": False, "limitations": template["limitations"]}
        code = 0
    except OSError as exc:
        report = {"schema": "dynamic-lab-handoff-export.v1", "status": "failed", "output": str(output), "qualified": False,
                  "errors": [{"code": "handoff_export_failed", "detail": type(exc).__name__}]}
        code = 3
    if args.report:
        target = Path(args.report); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Lab handoff export: {output} | status={report['status']} | qualified=False")
    return code


def cmd_release_build(args: argparse.Namespace) -> int:
    """Build a release manifest only after hashing material for all gates."""
    output = Path(args.out)
    report: dict[str, object]
    try:
        if args.release_root and args.commit and args.toolchain_lock and args.corpus_lock and args.gate_evidence:
            root = Path(args.release_root).resolve(strict=True)
            if not root.is_dir():
                raise ReleaseManifestBuildError("release_root_invalid")

            def lock_digest(value: str) -> str:
                supplied = Path(value)
                if supplied.is_symlink() or (hasattr(supplied, "is_junction") and supplied.is_junction()):
                    raise ReleaseManifestBuildError("release_lock_path_invalid")
                for parent in supplied.parents:
                    if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
                        raise ReleaseManifestBuildError("release_lock_path_invalid")
                material = supplied.resolve(strict=True)
                material.relative_to(root)
                if not material.is_file():
                    raise ReleaseManifestBuildError("release_lock_path_invalid")
                digest = _sha256_file(material)
                if not digest:
                    raise ReleaseManifestBuildError("release_lock_unreadable")
                return digest

            manifest = build_release_manifest(
                root,
                commit=args.commit,
                toolchain_lock_sha256=lock_digest(args.toolchain_lock),
                corpus_lock_sha256=lock_digest(args.corpus_lock),
                gate_evidence_paths=args.gate_evidence,
            )
            relative_manifest = Path(args.manifest_out)
            if relative_manifest.is_absolute() or ".." in relative_manifest.parts:
                raise ReleaseManifestBuildError("release_manifest_path_invalid")
            manifest_path = root / relative_manifest
            if any(part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()) for part in (manifest_path, *manifest_path.parents) if part != root.parent):
                raise ReleaseManifestBuildError("release_manifest_path_invalid")
            manifest_path.resolve().relative_to(root)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            encoded = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
            report = {"schema": "release-build.v1", "status": "ready", "manifest_built": True,
                      "manifest_path": str(manifest_path), "manifest_sha256": _sha256_file(manifest_path),
                      "blocking_gates": [], "errors": [],
                      "limitations": ["manifest materialization does not itself authorize release promotion"]}
            code = 0
        else:
            blockers: list[str] = ["release_evidence_arguments_missing"]
            if args.phase_report:
                gates = json.loads(Path(args.phase_report).read_text(encoding="utf-8"))
                if not isinstance(gates, dict) or gates.get("schema") != "phase-gate-report.v1" or not isinstance(gates.get("phases"), list):
                    raise ValueError("phase_report_invalid")
                expected = {f"F{index:02d}" for index in range(13)}
                statuses = {row.get("phase_id"): row.get("status") for row in gates["phases"] if isinstance(row, dict)}
                blockers = sorted(phase for phase in expected if statuses.get(phase) != "QUITADA")
            report = {"schema": "release-build.v1", "status": "blocked", "manifest_built": False,
                      "blocking_gates": blockers,
                      "errors": [{"code": "release_manifest_builder_inputs_missing"}],
                      "limitations": ["gate status text alone never proves a release manifest"]}
            code = 3
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
        report = {"schema": "release-build.v1", "status": "invalid", "manifest_built": False, "blocking_gates": ["phase_report_invalid"],
                  "errors": [{"code": "release_build_input_invalid", "detail": type(exc).__name__}]}
        code = 3
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Release build: {output} | status={report['status']} | manifest_built={report['manifest_built']} | blockers={len(report['blocking_gates'])}")
    return code


def cmd_release_inventory(args: argparse.Namespace) -> int:
    """Create a file inventory only; never infer or promote gate truth."""
    try:
        report = create_release_inventory(
            args.root,
            args.files,
            output=args.out,
            gate_claims=args.gate_claim,
        )
    except ReleaseInventoryError as exc:
        print(f"Release inventory: status=failed | reason={exc}")
        return 3
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Release inventory: status=failed | reason=inventory_input_invalid:{type(exc).__name__}")
        return 3
    print(
        f"Release inventory: {Path(args.root) / Path(args.out)} | status={report['inventory_status']} "
        f"| listed={report['summary']['listed']} | present={report['summary']['present']} "
        "| certified=False | promoted=0"
    )
    return 0


def cmd_corpus_registry_validate(args: argparse.Namespace) -> int:
    """Hash and validate a registered corpus without opening blind labels."""
    report = validate_corpus_registry(
        args.registry,
        args.root,
        blind_oracle_path=args.blind_oracle,
        blind_attestation_path=args.blind_attestation,
        trust_map_path=args.trust_map,
    )
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Corpus registry: {output} | status={report['status']} | entries={report['entry_count']}")
    return 0 if report["status"] == "QUITADA" else 3


def cmd_campaign_run(args: argparse.Namespace) -> int:
    """Run a declared local validation campaign with no shell expansion."""
    output = Path(args.out)
    try:
        document = json.loads(Path(args.campaign).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or set(document) != {"schema", "cases"} or document["schema"] != "validation-campaign-input.v1" or not isinstance(document["cases"], list):
            raise ValueError("campaign_schema_invalid")
        allowed = {"case_id", "category", "command", "expected_exit", "expected_codes", "timeout_s", "capability_optional", "evidence_files", "evidence_schema", "evidence_status", "minimum_evidence_cases"}
        cases = []
        for raw in document["cases"]:
            if not isinstance(raw, dict) or set(raw) - allowed:
                raise ValueError("campaign_case_schema_invalid")
            cases.append(CampaignCase(
                case_id=raw.get("case_id"), category=raw.get("category"), command=tuple(raw.get("command", [])),
                expected_exit=raw.get("expected_exit"), expected_codes=tuple(raw.get("expected_codes", [])),
                timeout_s=raw.get("timeout_s"), capability_optional=raw.get("capability_optional", False),
                evidence_files=tuple(raw.get("evidence_files", [])), evidence_schema=raw.get("evidence_schema"),
                evidence_status=raw.get("evidence_status"), minimum_evidence_cases=raw.get("minimum_evidence_cases", 0),
            ))
        report = run_validation_campaign(cases, root=Path(args.root), output=output,
                                         max_cases=args.max_cases, max_output_bytes=args.max_output_bytes)
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        report = {"schema": "validation-campaign.v1", "status": "failed", "cases": [],
                  "summary": {"total": 0, "passed": 0, "failed": 0, "partial": 0, "categories": []},
                  "errors": [{"code": "campaign_input_invalid", "detail": str(exc) if str(exc).isalnum() else type(exc).__name__}],
                  "execution": {"shell": False, "target_execution": False, "network_required": False}}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"Campaign: {output} | status={report['status']} | cases={report['summary']['total']}")
    return 0 if report["status"] == "passed" else 3

def cmd_firmware_qualify(args: argparse.Namespace) -> int:
    report=qualify_firmware_layout(Path(args.input),Path(args.layout))
    output=Path(args.out);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding='utf-8',newline='\n')
    print(f"Firmware layout: {args.out} | qualified={report['qualified']}")
    return 0 if report['qualified'] else 3


def cmd_documentation_audit(args: argparse.Namespace) -> int:
    """Audit documentation metadata and local links without executing content."""
    report = audit_documentation(
        Path(args.root),
        max_files=args.max_files,
        max_bytes=args.max_bytes,
        max_file_bytes=args.max_file_bytes,
    )
    write_documentation_report(report, Path(args.out))
    summary = report.get("summary", {})
    print(f"Documentation audit: {args.out} | status={report['status']} | documents={summary.get('documents', 0)} | unresolved={summary.get('local_unresolved', 0)}")
    return 0 if report.get("status") in {"complete", "not_found"} else 2


def cmd_graph_ingest(args: argparse.Namespace) -> int:
    """Persist a supplied graph projection; never imports the analyzed project."""
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {"schema": "graph-store.v1", "status": "invalid", "errors": [{"code": "input_unreadable", "detail": type(exc).__name__}], "stats": {"nodes": 0, "edges": 0}, "inserted_nodes": 0, "inserted_edges": 0, "limitations": ["não executa projeto analisado"]}
    else:
        report = ingest_graph(Path(args.db), data, run_id=args.run_id, max_nodes=args.max_nodes, max_edges=args.max_edges)
    write_graph_report(report, Path(args.out))
    print(f"Graph ingest: {args.out} | status={report['status']} | nodes={report.get('inserted_nodes', 0)} | edges={report.get('inserted_edges', 0)}")
    return 0 if report.get("status") == "complete" else 2


def cmd_graph_verify(args: argparse.Namespace) -> int:
    report = verify_graph_store(Path(args.db))
    write_graph_report(report, Path(args.out))
    print(f"Graph verify: {args.db} | status={report['status']} | errors={len(report.get('errors', []))}")
    return 0 if report.get("status") == "pass" else 2


def cmd_graph_node(args: argparse.Namespace) -> int:
    report = get_node(Path(args.db), args.node_id)
    write_graph_report(report, Path(args.out))
    print(f"Graph node: {args.node_id} | status={report['status']}")
    return 0 if report.get("status") == "complete" else 2


def cmd_doctor(args: argparse.Namespace) -> int:
    report = diagnose_tools()
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for name, item in report["tools"].items():
            print(f"{name}: {'OK' if item['available'] else 'MISSING'} {item.get('path') or ''}")
    return 0


def cmd_homologate(args: argparse.Namespace) -> int:
    target = Path(args.target) if args.target else None
    report = audit_run_package(Path(args.run_dir), target=target)
    write_homologation_report(report, Path(args.out))
    print(f"Homologation: {args.out} | status={report['status']} | issues={len(report['issues'])}")
    return 0 if report["status"] == "pass" else 2


def cmd_project_inventory(args: argparse.Namespace) -> int:
    report = inventory_project(
        Path(args.root),
        max_files=args.max_files,
        max_bytes=args.max_bytes,
        max_file_bytes=args.max_file_bytes,
    )
    write_inventory_report(report, Path(args.out))
    summary = report.get("summary", {})
    print(f"Project inventory: {args.out} | status={report['status']} | files={summary.get('files', 0)} | skipped={len(report.get('skipped', []))}")
    return 0 if report["status"] == "complete" else 2



def _write_intake_result(value: dict[str, object], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

def normalize_intake_error(exc: BaseException) -> str:
    if isinstance(exc, FileNotFoundError): return "authorization_unreadable"
    if isinstance(exc, json.JSONDecodeError): return "authorization_invalid_json"
    message = str(exc)
    return message if re.fullmatch(r"[a-z0-9_:.\-]{1,128}", message) else type(exc).__name__.lower()

def cmd_intake(args: argparse.Namespace) -> int:
    result_path = Path(args.result)
    try:
        try:
            policy = AuthorizationPolicy.from_dict(json.loads(Path(args.authorization).read_text(encoding="utf-8")))
        except FileNotFoundError:
            raise IntakeRejected("authorization_unreadable")
        limits = IntakeLimits.from_dict({"max_files": args.max_files, "max_total_bytes": args.max_total_bytes, "max_file_bytes": args.max_file_bytes, "max_archive_depth": args.max_archive_depth, "max_compression_ratio": args.max_compression_ratio, "max_path_length": args.max_path_length})
        intake = prepare_case(IntakeRequest(Path(args.source), Path(args.case_dir), policy, limits, not args.no_expand_archives))
        report = {"schema":"intake-cli-result.v1","status":"complete","case_id":intake.case_id,"manifest":str(intake.manifest_path)}; code=0
    except (OSError, json.JSONDecodeError, ContractError, IntakeRejected) as exc:
        report = {"schema":"intake-cli-result.v1","status":"rejected","error":normalize_intake_error(exc)}; code=2
    _write_intake_result(report, result_path)
    return code


def cmd_universal(args: argparse.Namespace) -> int:
    """Run the default static-only universal pipeline."""
    report = run_universal_case(Path(args.target), Path(args.out), CasePolicy.static_only())
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    return 0

def main() -> int:
    p = argparse.ArgumentParser(
        prog="megazord",
        description="AetherRE Megazord — engenharia reversa / forense de binários",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    intake = sub.add_parser("intake", help="Cria caso forense autorizado sem executar o alvo")
    intake.add_argument("source")
    intake.add_argument("--case-dir", required=True)
    intake.add_argument("--authorization", required=True)
    intake.add_argument("--result", required=True)
    intake.add_argument("--no-expand-archives", action="store_true")
    intake.add_argument("--max-files", type=int, default=10000)
    intake.add_argument("--max-total-bytes", type=int, default=2 * 1024 * 1024 * 1024)
    intake.add_argument("--max-file-bytes", type=int, default=512 * 1024 * 1024)
    intake.add_argument("--max-archive-depth", type=int, default=3)
    intake.add_argument("--max-compression-ratio", type=int, default=200)
    intake.add_argument("--max-path-length", type=int, default=512)
    intake.set_defaults(func=cmd_intake)

    universal = sub.add_parser("universal", help="Pipeline universal fail-closed (estático por padrão)")
    universal.add_argument("target", help="Artefato alvo autorizado")
    universal.add_argument("--out", required=True, help="Diretório novo de saída")
    universal.set_defaults(func=cmd_universal)


    s = sub.add_parser("status", help="Estado dos motores e adapters")
    s.set_defaults(func=cmd_status)

    a = sub.add_parser("analyze", help="Analisar um binário/artefacto")
    a.add_argument("target", help="Caminho do ficheiro alvo")
    a.add_argument("--out", help="Pasta de output")
    a.add_argument("--no-adapters", action="store_true", help="Só motores nativos")
    a.add_argument("--shallow", action="store_true", help="Sem disasm profundo")
    a.add_argument("--reuse-cache", action="store_true", help="Reutiliza uma execução validada em --out")
    a.add_argument("--profile", choices=("native-pe", "native-elf", "dotnet", "android-apk", "wasm", "macho", "jvm", "firmware"), help="Perfil estático exigido")
    a.set_defaults(func=cmd_analyze)

    inspect = sub.add_parser("inspect", help="Alias de analyze para inspeção estática autorizada")
    inspect.add_argument("target", help="Caminho do ficheiro alvo")
    inspect.add_argument("--out", help="Pasta de output")
    inspect.add_argument("--no-adapters", action="store_true", help="Só motores nativos")
    inspect.add_argument("--shallow", action="store_true", help="Sem disasm profundo")
    inspect.add_argument("--reuse-cache", action="store_true", help="Reutiliza uma execução validada em --out")
    inspect.add_argument("--profile", default=None, choices=("auto", "native-pe", "native-elf", "dotnet", "android-apk", "wasm", "macho", "jvm", "firmware"), help="Perfil exigido; auto é detecção")
    inspect.set_defaults(func=cmd_analyze)

    t = sub.add_parser("selftest", help="Teste rápido com notepad/python")
    t.set_defaults(func=cmd_selftest)

    src = sub.add_parser("source-analyze", help="Leitura AST estática de um projeto Python (sem execução)")
    src.add_argument("root", help="Raiz do projeto Python")
    src.add_argument("--out", help="Caminho do relatório JSON")
    src.set_defaults(func=cmd_source_analyze)

    csrc = sub.add_parser("c-source-analyze", help="Leitura estática heurística de projeto C/C++ (sem compilar/executar)")
    csrc.add_argument("root", help="Raiz do projeto C/C++")
    csrc.add_argument("--out", required=True, help="Relatório JSON")
    csrc.set_defaults(func=cmd_c_source_analyze)

    ba = sub.add_parser("build-audit", help="Audita receitas/flags de build sem compilar ou executar")
    ba.add_argument("root", help="Raiz do projeto")
    ba.add_argument("--out", required=True, help="Relatório JSON")
    ba.add_argument("--max-files", type=int, default=200)
    ba.add_argument("--max-file-bytes", type=int, default=4 * 1024 * 1024)
    ba.set_defaults(func=cmd_build_audit)

    bl = sub.add_parser("build-link", help="Liga build declarado a binário por output e hashes, sem executar")
    bl.add_argument("--build-report", required=True, help="Relatório build-audit.json")
    bl.add_argument("--binary", required=True, help="Binário observado")
    bl.add_argument("--binary-report", help="Relatório da análise binária com target_sha256")
    bl.add_argument("--out", required=True, help="Relatório JSON da ligação")
    bl.set_defaults(func=cmd_build_link)

    rp = sub.add_parser("repro-pack", help="Cria pacote ZIP determinístico de uma execução homologada")
    rp.add_argument("run_dir", help="Pasta de output")
    rp.add_argument("--out", required=True, help="ZIP de reprodução")
    rp.add_argument("--report", help="Relatório JSON da criação")
    rp.add_argument("--allow-partial", action="store_true", help="Permite empacotar execução não homologada (status explícito)")
    rp.set_defaults(func=cmd_repro_pack)

    rv = sub.add_parser("repro-verify", help="Verifica pacote ZIP sem extrair nem executar conteúdo")
    rv.add_argument("package", help="ZIP de reprodução")
    rv.add_argument("--out", help="Relatório JSON")
    rv.set_defaults(func=cmd_repro_verify)

    rr = sub.add_parser("repro-restore", help="Restaura somente artefatos de um pacote verificado, sem executar conteúdo")
    rr.add_argument("package", help="ZIP de reprodução verificado")
    rr.add_argument("destination", help="Diretório novo de destino; não sobrescreve diretório existente")
    rr.add_argument("--out", help="Relatório JSON")
    rr.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)
    rr.set_defaults(func=cmd_repro_restore)

    pa = sub.add_parser("project-audit", help="Auditoria estática integrada de inventário, fonte e build")
    pa.add_argument("root", help="Raiz do projeto")
    pa.add_argument("--out", required=True, help="Relatório JSON")
    pa.set_defaults(func=cmd_project_audit)

    ps = sub.add_parser("project-snapshot", help="Copia escopo inventariado para snapshot local verificável, sem executar alvo")
    ps.add_argument("root", help="Raiz do projeto")
    ps.add_argument("destination", help="Diretório novo de destino, fora da raiz")
    ps.add_argument("--report", help="Relatório JSON da criação")
    ps.add_argument("--max-files", type=int, default=5000)
    ps.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024)
    ps.add_argument("--max-file-bytes", type=int, default=16 * 1024 * 1024)
    ps.add_argument("--immutable", action="store_true", help="Sela arquivos locais como read-only; não é WORM/custódia externa")
    ps.set_defaults(func=cmd_project_snapshot)

    cc = sub.add_parser("custody-create", help="Cria recibo local hash-chain de artefatos sem copiá-los")
    cc.add_argument("--artifact", action="append", required=True, metavar="NOME=CAMINHO", help="Artefato regular; pode repetir")
    cc.add_argument("--out", required=True, help="Recibo JSON novo")
    cc.add_argument("--report", help="Relatório JSON")
    cc.add_argument("--previous", help="Recibo anterior para encadear")
    cc.add_argument("--metadata", help="Objeto JSON adicional")
    cc.add_argument("--immutable", action="store_true", help="Torna o recibo local read-only; não é WORM")
    cc.set_defaults(func=cmd_custody_create)

    cv = sub.add_parser("custody-verify", help="Verifica recibo local e hashes dos artefatos")
    cv.add_argument("receipt", help="Recibo JSON")
    cv.add_argument("--out", help="Relatório JSON")
    cv.add_argument("--require-sealed", action="store_true", help="Exige recibo read-only")
    cv.set_defaults(func=cmd_custody_verify)

    pv = sub.add_parser("project-snapshot-verify", help="Verifica arquivos/hashes do snapshot local sem executar conteúdo")
    pv.add_argument("destination", help="Diretório de snapshot")
    pv.add_argument("--expected-manifest-sha256", help="Hash do manifesto obtido fora do snapshot")
    pv.add_argument("--require-sealed", action="store_true", help="Exige selo local read-only verificável")
    pv.add_argument("--max-total-bytes", type=int, default=512 * 1024 * 1024)
    pv.add_argument("--report", help="Relatório JSON")
    pv.set_defaults(func=cmd_project_snapshot_verify)

    ev = sub.add_parser("evidence-validate", help="Valida contrato/proveniência de registros de evidência")
    ev.add_argument("--input", required=True, help="JSON com evidence")
    ev.add_argument("--manifest", help="Manifesto para validar raw_artifact_hash")
    ev.add_argument("--out", required=True, help="Relatório JSON")
    ev.add_argument("--strict", action="store_true", help="Exige campos completos de proveniência")
    ev.set_defaults(func=cmd_evidence_validate)

    everify = sub.add_parser("evidence-verify", help="Alias de evidence-validate para verificação fail-closed")
    everify.add_argument("manifest", nargs="?", help="manifesto opcional que vincula raw_artifact_hash")
    everify.add_argument("--input", required=True, help="JSON com evidence")
    everify.add_argument("--out", required=True, help="Relatório JSON")
    everify.add_argument("--strict", action="store_true", help="Exige campos completos de proveniência")
    everify.set_defaults(func=lambda args: cmd_evidence_validate(argparse.Namespace(input=args.input, manifest=args.manifest, out=args.out, strict=args.strict)))

    pd = sub.add_parser("project-dependencies", help="Audita dependências declaradas/observadas em vários ecossistemas")
    pd.add_argument("root", help="Raiz do projeto")
    pd.add_argument("--out", required=True, help="Relatório JSON")
    pd.set_defaults(func=cmd_project_dependencies)

    tc = sub.add_parser("trace-correlate", help="Correlaciona trace externo com mapas estáticos sem executar alvo")
    tc.add_argument("--input", required=True, help="JSON dynamic-trace.v1")
    tc.add_argument("--source-report", help="Relatório source-analyze opcional")
    tc.add_argument("--binary-report", help="Relatório analyze opcional")
    tc.add_argument("--out", required=True, help="Relatório JSON")
    tc.set_defaults(func=cmd_trace_correlate)

    sf = sub.add_parser("sarif", help="Exporta achados para SARIF 2.1.0")
    sf.add_argument("--input", required=True, help="Relatório JSON")
    sf.add_argument("--out", required=True, help="Arquivo SARIF")
    sf.set_defaults(func=cmd_sarif)

    rh = sub.add_parser("review-html", help="Gera revisão HTML offline de um relatório, sem recursos externos")
    rh.add_argument("--input", required=True, help="Relatório JSON")
    rh.add_argument("--out", required=True, help="Arquivo HTML")
    rh.add_argument("--title", default="AetherRE Forensic Review")
    rh.set_defaults(func=cmd_review_html)

    bm = sub.add_parser("benchmark-static", help="Mede inventário/build-audit estáticos sem executar alvo")
    bm.add_argument("root", help="Raiz do projeto")
    bm.add_argument("--out", required=True, help="Relatório JSON")
    bm.add_argument("--iterations", type=int, default=3)
    bm.set_defaults(func=cmd_benchmark_static)

    ef = sub.add_parser("effects-validate", help="Valida efeitos de trace contra política de escopo, sem executar alvo")
    ef.add_argument("--input", required=True, help="JSON com events")
    ef.add_argument("--out", required=True, help="Relatório JSON")
    ef.add_argument("--allowed-root", action="append", default=[], help="Raiz permitida para efeitos de arquivo (repetível)")
    ef.add_argument("--network-enabled", action="store_true")
    ef.add_argument("--writable-project", action="store_true")
    ef.add_argument("--max-events", type=int, default=100000)
    ef.set_defaults(func=cmd_effects_validate)

    ce = sub.add_parser("corpus-evaluate", help="Mede leitor estático contra oracles do corpus sem executar alvos")
    ce.add_argument("manifest", help="manifest.json do corpus")
    ce.add_argument("--out", required=True, help="Relatório JSON")
    ce.set_defaults(func=cmd_corpus_evaluate)

    ceb = sub.add_parser("corpus-evaluate-binaries", help="Avalia símbolos/DWARF de binários C construídos explicitamente")
    ceb.add_argument("manifest", help="manifest.json do corpus")
    ceb.add_argument("--build-report", required=True, help="build_report.json produzido por corpus-build-native")
    ceb.add_argument("--out", required=True, help="Relatório JSON")
    ceb.add_argument("--measure-direct-calls", action="store_true", help="mede calls diretos locais ELF x86/x86_64 com Capstone (estático; indiretos permanecem não medidos)")
    ceb.add_argument("--dia-helper", help="helper DIA explícito para ler PDB; exige --dia-dll")
    ceb.add_argument("--dia-dll", help="msdia140.dll explícita; exige --dia-helper")
    ceb.add_argument("--pdb-timeout", type=float, default=90.0, help="timeout por PDB no helper DIA")
    ceb.add_argument("--pdb-max-symbols", type=int, default=50000, help="limite de símbolos por PDB")
    ceb.set_defaults(func=cmd_corpus_evaluate_binaries)

    bpc = sub.add_parser("compare-binary-profiles", help="Compara avaliações dos mesmos projetos entre perfis de build, sem executar binários")
    bpc.add_argument("--baseline", required=True, help="Avaliação do perfil de referência")
    bpc.add_argument("--candidate", required=True, help="Avaliação do perfil candidato")
    bpc.add_argument("--out", required=True, help="Relatório JSON")
    bpc.set_defaults(func=cmd_compare_binary_profiles)

    cv = sub.add_parser("corpus-validate", help="Valida receitas do corpus sem executar binários")
    cv.add_argument("manifest", help="manifest.json do corpus")
    cv.add_argument("--out", help="relatório de build")
    cv.set_defaults(func=cmd_corpus_validate)

    crv = sub.add_parser("corpus-registry-validate", help="Recalcula lock do corpus por hash e valida blind oracle separado")
    crv.add_argument("--registry", required=True, help="corpus-registry.v1")
    crv.add_argument("--root", required=True, help="raiz material do corpus")
    crv.add_argument("--blind-oracle", help="arquivo separado blind-oracle.v1")
    crv.add_argument("--blind-attestation", help="atestação Ed25519 do proprietário independente do oracle")
    crv.add_argument("--trust-map", help="trust map Ed25519 fora do checkout e do corpus")
    crv.add_argument("--out", required=True, help="relatório e lock calculado")
    crv.set_defaults(func=cmd_corpus_registry_validate)

    cb = sub.add_parser("corpus-build-native", help="Compila C do corpus somente em worker WSL explícito")
    cb.add_argument("manifest", help="manifest.json do corpus")
    cb.add_argument("--out", required=True, help="diretório separado para os binários gerados")
    cb.add_argument("--report", help="relatório JSON de build (padrão: out/build_report.json)")
    cb.add_argument("--timeout", type=float, default=60.0, help="timeout por projeto")
    cb.add_argument("--memory-mb", type=int, default=1024, help="limite RSS aproximado do worker")
    cb.add_argument("--opt-level", choices=["-O0", "-O1", "-O2", "-O3", "-Os"], default="-O0", help="perfil de otimização")
    cb.add_argument("--no-debug", action="store_true", help="não incluir DWARF -g")
    cb.add_argument("--strip", action="store_true", help="remover símbolos no worker (limite deliberado)")
    cb.set_defaults(func=cmd_corpus_build_native)
    cm = sub.add_parser("corpus-build-msvc", help="Compila C autorizado com worker MSVC explícito; nunca executa os PE")
    cm.add_argument("manifest", help="manifest.json do corpus")
    cm.add_argument("--out", required=True, help="diretório separado para os PE gerados")
    cm.add_argument("--compiler", required=True, help="caminho absoluto para cl.exe")
    cm.add_argument("--vcvarsall", required=True, help="caminho absoluto para vcvarsall.bat")
    cm.add_argument("--support-dir", required=True, help="testcasesupport com headers e io.c")
    cm.add_argument("--report", help="relatório JSON de build (padrão: out/build_report.json)")
    cm.add_argument("--timeout", type=float, default=120.0, help="timeout por projeto")
    cm.add_argument("--memory-mb", type=int, default=2048, help="limite RSS aproximado do worker")
    cm.add_argument("--opt-level", choices=["-O0", "-O1", "-O2", "-O3", "-Os"], default="-O0", help="perfil de otimização")
    cm.add_argument("--no-debug", action="store_true", help="não incluir PDB/debug")
    cm.add_argument("--allow-external-authorized", action="store_true", help="autoriza explicitamente corpus external_authorized")
    cm.set_defaults(func=cmd_corpus_build_msvc)

    co = sub.add_parser("correlate", help="Correlaciona candidatos fonte↔binário sem afirmar equivalência")
    co.add_argument("--source-report", required=True)
    co.add_argument("--binary-report", required=True)
    co.add_argument("--build-report", help="Relatório build-audit.json opcional; somente proveniência declarada")
    co.add_argument("--out", required=True)
    co.set_defaults(func=cmd_correlate)

    da = sub.add_parser("dependencies-audit", help="Audita dependências declaradas versus imports estáticos")
    da.add_argument("root", help="Raiz do projeto Python")
    da.add_argument("--out", required=True, help="Relatório JSON")
    da.set_defaults(func=cmd_dependencies_audit)

    ra = sub.add_parser("risk-audit", help="Audita indicadores estáticos de risco em relatório Python")
    ra.add_argument("--source-report", required=True)
    ra.add_argument("--project-root", help="Raiz opcional para fluxo de dados intraprocedural")
    ra.add_argument("--out", required=True)
    ra.set_defaults(func=cmd_risk_audit)

    tr = sub.add_parser("trace-validate", help="Valida contrato/continuidade de trace sem executar alvo")
    tr.add_argument("--input", required=True)
    tr.add_argument("--out", required=True)
    tr.add_argument("--max-events", type=int, default=100000)
    tr.set_defaults(func=cmd_trace_validate)

    lp = sub.add_parser("lab-preflight", help="Valida política de laboratório sem executar alvo")
    lp.add_argument("--isolation", default="none", choices=["vm", "container", "host", "none"])
    lp.add_argument("--authorized", action="store_true")
    lp.add_argument("--network", action="store_true")
    lp.add_argument("--writable-mount", action="store_true")
    lp.add_argument("--host-execution", action="store_true")
    lp.add_argument("--runtime-proof", action="store_true", help="Exige snapshot descartável, rollback, collector e budgets declarados")
    lp.add_argument("--snapshot-id", help="Identificador do snapshot descartável (declarativo)")
    lp.add_argument("--rollback", action="store_true", help="Declara rollback habilitado")
    lp.add_argument("--collector-configured", action="store_true", help="Declara collector externo configurado")
    lp.add_argument("--timeout-s", type=int, default=0, help="Budget de tempo declarativo")
    lp.add_argument("--memory-mb", type=int, default=0, help="Budget de memória declarativo")
    lp.add_argument("--proof", help="JSON de prova materializada do guest; valida sem executar o alvo")
    lp.set_defaults(func=cmd_lab_preflight)

    dc = sub.add_parser("differential-compare", help="Compara observações original/reconstruída sem executar alvos")
    dc.add_argument("--original", required=True)
    dc.add_argument("--reconstructed", required=True)
    dc.add_argument("--out", required=True)
    dc.add_argument("--max-observations", type=int, default=100000)
    dc.set_defaults(func=cmd_differential_compare)

    bc = sub.add_parser("behavior-compare", help="Valida atestações e compara somente observações guest assinadas")
    bc.add_argument("--input", required=True, help="relatório behavioral-run.v1")
    bc.add_argument("--trust-map", help="trust map externo aetherre-trust-map.v1 (chaves públicas Ed25519)")
    bc.add_argument("--out", required=True)
    bc.set_defaults(func=cmd_behavior_compare)

    fs = sub.add_parser("fuzz-seeds", help="Gera mutações determinísticas sem executar o alvo")
    fs.add_argument("--input", required=True, help="JSON com seeds em hexadecimal")
    fs.add_argument("--out", required=True)
    fs.add_argument("--budget", type=int, default=100)
    fs.add_argument("--max-size", type=int, default=4096)
    fs.set_defaults(func=cmd_fuzz_seeds)

    mt = sub.add_parser("metrics", help="Calcula precisão/recall/Brier/ECE com labels fornecidos")
    mt.add_argument("--input", required=True, help="JSON com predictions: label e score")
    mt.add_argument("--out", required=True)
    mt.add_argument("--bins", type=int, default=10)
    mt.add_argument("--group-by", help="Campo opcional para métricas estratificadas (ex.: family/language)")
    mt.set_defaults(func=cmd_metrics)

    mh = sub.add_parser("metrics-holdout", help="Avalia holdout cego por família com proveniência e calibração declarada")
    mh.add_argument("--input", required=True, help="JSON com predictions e campos sample_id/evidence_id/family/split/label/score/producer")
    mh.add_argument("--out", required=True)
    mh.add_argument("--bins", type=int, default=10)
    mh.add_argument("--calibration-frozen", action="store_true", help="Declara que a calibração foi congelada antes do holdout")
    mh.add_argument("--minimum-samples", type=int, default=0, help="Mínimo declarado por split; 0 não aplica política")
    mh.add_argument("--minimum-families", type=int, default=0, help="Mínimo declarado de famílias por split; 0 não aplica política")
    mh.set_defaults(func=cmd_metrics_holdout)

    cl = sub.add_parser("claims-validate", help="Valida alegações contra evidências sem promover narrativa")
    cl.add_argument("--claims", required=True)
    cl.add_argument("--evidence", required=True)
    cl.add_argument("--out", required=True)
    cl.add_argument("--strict-evidence", action="store_true", help="Exige contrato estrito de proveniência")
    cl.add_argument("--manifest", help="Manifesto para vincular raw_artifact_hash")
    cl.add_argument("--profile-scope", help="JSON de perfil congelado; impede claims universais")
    cl.set_defaults(func=cmd_claims_validate)

    ap = sub.add_parser("assist-propose", help="Propõe hipóteses/experimentos offline a partir de evidências")
    ap.add_argument("--input", required=True, help="JSON com evidence/records")
    ap.add_argument("--out", required=True, help="Relatório JSON")
    ap.add_argument("--question", default="", help="Pergunta contextual, tratada como dado não confiável")
    ap.add_argument("--max-hypotheses", type=int, default=50)
    ap.add_argument("--strict-evidence", action="store_true")
    ap.set_defaults(func=cmd_assist_propose)

    av = sub.add_parser("assist-verify", help="Verifica citações das hipóteses sem promovê-las a fato")
    av.add_argument("--proposals", required=True, help="JSON produzido por assist-propose ou lista de propostas")
    av.add_argument("--evidence", required=True, help="JSON com evidence/records")
    av.add_argument("--out", required=True, help="Relatório JSON")
    av.add_argument("--strict-evidence", action="store_true")
    av.set_defaults(func=cmd_assist_verify)

    sy = sub.add_parser("symbolic-validate", help="Valida artefato externo de exploração simbólica sem executar solver/alvo")
    sy.add_argument("--input", required=True, help="JSON symbolic-exploration.v1 produzido por worker isolado")
    sy.add_argument("--out", required=True, help="Relatório JSON validado")
    sy.add_argument("--max-paths", type=int, default=10000, help="Limite máximo de paths aceitos")
    sy.set_defaults(func=cmd_symbolic_validate)

    pg = sub.add_parser("phase-gates", help="Avalia gates F00-F12 contra declarações e evidências hashadas, sem executar testes/alvos")
    pg.add_argument("--input", required=True, help="JSON com lista de phases")
    pg.add_argument("--root", help="Raiz sob a qual os caminhos de evidência devem permanecer")
    pg.add_argument("--out", required=True, help="Relatório JSON dos gates")
    pg.add_argument("--max-evidence", type=int, default=10000)
    pg.set_defaults(func=cmd_phase_gates)

    rc = sub.add_parser("release-certify", help="Certifica release materializada contra revisão independente Ed25519")
    rc.add_argument("--manifest", required=True, help="release-manifest.v1")
    rc.add_argument("--review", required=True, help="independent-review.v1")
    rc.add_argument("--trust-map", required=True, help="Mapa externo reviewer -> chave pública Ed25519")
    rc.add_argument("--release-root", required=True, help="Raiz que contém as evidências hashadas da release")
    rc.add_argument("--out", required=True, help="release-certification.v1")
    rc.set_defaults(func=cmd_release_certify)

    lq = sub.add_parser("lab-qualify", help="Valida handoff de VM real sem executar guest ou amostra")
    lq.add_argument("--input", required=True, help="dynamic-lab-handoff.v1")
    lq.add_argument("--out", required=True, help="Relatório de qualificação")
    lq.set_defaults(func=cmd_lab_qualify)

    tv = sub.add_parser("toolchain-verify", help="Recalcula hashes da toolchain bloqueada sem executar workers")
    tv.add_argument("--lock", required=True, help="toolchain-lock.v1")
    tv.add_argument("--jar-lock", help="jar-workers-lock.v1 optional; rehashes Java runtime and archive")
    tv.add_argument("--out", required=True, help="Relatório de verificação")
    tv.set_defaults(func=cmd_toolchain_verify)

    pc = sub.add_parser("profile-certify", help="Recalcula certificado estático delimitado a partir de evidências JSON")
    pc.add_argument("--profile-scope", required=True, help="profile-scope.v1 delimitado")
    pc.add_argument("--corpus", required=True, help="corpus lock com hashes development/calibration/blind")
    pc.add_argument("--workers", required=True, help="worker lock materializado")
    pc.add_argument("--evaluation", required=True, help="medidas e evidências de oracle independente")
    pc.add_argument("--baseline", required=True, help="baseline de regressões")
    pc.add_argument("--evidence-root", help="raiz material das evidências assinadas do perfil")
    pc.add_argument("--trust-map", help="trust map Ed25519 governado fora do repositório/evidence-root")
    pc.add_argument("--out", required=True, help="certificado recalculado")
    pc.set_defaults(func=cmd_profile_certify)

    pp = sub.add_parser("profile-probe", help="Detecta perfil estático e expõe seu envelope; não certifica")
    pp.add_argument("input", help="Artefato autorizado a identificar")
    pp.add_argument("--out", help="Relatório JSON opcional")
    pp.set_defaults(func=cmd_profile_probe)

    le = sub.add_parser("lab-export-handoff", help="Exporta template de handoff para VM real; não qualifica laboratório")
    le.add_argument("--out", required=True, help="ZIP novo do pacote de handoff")
    le.add_argument("--report", help="relatório JSON do export")
    le.set_defaults(func=cmd_lab_export_handoff)

    rb = sub.add_parser("release-build", help="Constrói manifest a partir de evidência material dos 13 gates")
    rb.add_argument("--phase-report", help="phase-gate-report.v1 (somente diagnóstico; não aprova release)")
    rb.add_argument("--release-root", help="raiz fechada dos artefatos de release")
    rb.add_argument("--commit", help="commit Git exato de 40 caracteres")
    rb.add_argument("--toolchain-lock", help="lock materializado dentro de release-root")
    rb.add_argument("--corpus-lock", help="lock materializado dentro de release-root")
    rb.add_argument("--gate-evidence", nargs="+", help="13 caminhos gate-evidence.v1 relativos a release-root")
    rb.add_argument("--manifest-out", default="release-manifest.v1.json", help="caminho relativo novo dentro de release-root")
    rb.add_argument("--out", required=True, help="relatório de elegibilidade")
    rb.set_defaults(func=cmd_release_build)

    ri = sub.add_parser("release-inventory", help="Cria inventário parcial de arquivos sem certificar gates")
    ri.add_argument("--root", required=True, help="raiz confinada do inventário")
    ri.add_argument("--files", nargs="+", required=True, help="caminhos relativos explícitos a inventariar")
    ri.add_argument("--gate-claim", action="append", default=[], metavar="F00=STATUS", help="claim informativo; sempre não verificado")
    ri.add_argument("--out", required=True, help="caminho relativo novo dentro de root")
    ri.set_defaults(func=cmd_release_inventory)

    cr = sub.add_parser("campaign-run", help="Executa campanha declarada sem shell e com evidência por caso")
    cr.add_argument("campaign", help="validation-campaign-input.v1")
    cr.add_argument("--root", required=True, help="raiz confinada de execução/evidência")
    cr.add_argument("--out", required=True, help="relatório de campanha dentro da raiz")
    cr.add_argument("--max-cases", type=int, default=500)
    cr.add_argument("--max-output-bytes", type=int, default=1_048_576)
    cr.set_defaults(func=cmd_campaign_run)

    fq = sub.add_parser("firmware-qualify", help="Valida layout explícito e hash do blob; não executa firmware")
    fq.add_argument("--input", required=True, help="blob de firmware autorizado")
    fq.add_argument("--layout", required=True, help="firmware-layout.v1")
    fq.add_argument("--out", required=True, help="relatório de qualificação")
    fq.set_defaults(func=cmd_firmware_qualify)

    doc = sub.add_parser("documentation-audit", help="Audita documentação e links locais sem executar comandos ou código")
    doc.add_argument("root", help="Raiz do projeto")
    doc.add_argument("--out", required=True, help="Relatório JSON")
    doc.add_argument("--max-files", type=int, default=2000)
    doc.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    doc.add_argument("--max-file-bytes", type=int, default=4 * 1024 * 1024)
    doc.set_defaults(func=cmd_documentation_audit)

    gi = sub.add_parser("graph-ingest", help="Persiste grafo já produzido em SQLite sem executar o projeto analisado")
    gi.add_argument("--input", required=True, help="Relatório com graph ou grafo direto")
    gi.add_argument("--db", required=True, help="Banco SQLite da projeção")
    gi.add_argument("--run-id", required=True)
    gi.add_argument("--out", required=True, help="Relatório JSON")
    gi.add_argument("--max-nodes", type=int, default=100000)
    gi.add_argument("--max-edges", type=int, default=300000)
    gi.set_defaults(func=cmd_graph_ingest)

    gv = sub.add_parser("graph-verify", help="Verifica hashes internos do grafo SQLite sem modificar dados")
    gv.add_argument("--db", required=True)
    gv.add_argument("--out", required=True)
    gv.set_defaults(func=cmd_graph_verify)

    gn = sub.add_parser("graph-node", help="Consulta um nó imutável do grafo SQLite")
    gn.add_argument("--db", required=True)
    gn.add_argument("--node-id", required=True)
    gn.add_argument("--out", required=True)
    gn.set_defaults(func=cmd_graph_node)

    dr = sub.add_parser("doctor", help="Diagnostica ferramentas e caminhos sem instalar nada")
    dr.add_argument("--json", action="store_true")
    dr.set_defaults(func=cmd_doctor)

    hg = sub.add_parser("homologate", help="Audita integridade e completude de uma execução materializada")
    hg.add_argument("run_dir", help="Pasta de output de uma análise")
    hg.add_argument("--target", help="Alvo original para reconferir SHA256")
    hg.add_argument("--out", required=True, help="Relatório JSON")
    hg.set_defaults(func=cmd_homologate)

    pi = sub.add_parser("project-inventory", help="Inventário estático e limitado de arquivos do projeto")
    pi.add_argument("root", help="Raiz do projeto")
    pi.add_argument("--out", required=True, help="Relatório JSON")
    pi.add_argument("--max-files", type=int, default=5000)
    pi.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024)
    pi.add_argument("--max-file-bytes", type=int, default=16 * 1024 * 1024)
    pi.set_defaults(func=cmd_project_inventory)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
