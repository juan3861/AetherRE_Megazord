"""Pipeline principal do Megazord — engines nativas + ensemble por função."""

from __future__ import annotations

import atexit
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aether_re.adapters.angr import AngrAdapter
from aether_re.adapters.binaryninja import BinaryNinjaAdapter
from aether_re.adapters.frida_dyn import FridaAdapter
from aether_re.adapters.ghidra import GhidraAdapter
from aether_re.adapters.rizin import RizinAdapter
from aether_re.adapters.unicorn_emu import UnicornAdapter
from aether_re.adapters.wasm import WasmAdapter
from aether_re.adapters.android import AndroidAdapter
from aether_re.adapters.jvm import JvmAdapter
from aether_re.adapters.ilspy import ILSpyAdapter
from aether_re.engines import disasm, dwarf, pe_elf, reconstruct, strings_decode, triage
from aether_re.engines.comparative_report import generate_comparative_report
from aether_re.engines.consensus import (
    compute_overall_confidence,
    merge_function_evidence,
)
from aether_re.engines.decompiler import (
    GHIDRA_PARTIAL_CONFIDENCE_CAP,
    ghidra_result_is_complete,
    mark_ghidra_functions_partial,
    merge_decompilation_results,
)
from aether_re.engines.ghidra_parse import write_function_index
from aether_re.models import AnalysisReport, FunctionConsensus, FunctionEvidence
from aether_re.evidence import (
    _has_link_or_reparse_component,
    _is_hardlinked_regular_file,
    build_manifest,
    create_verified_snapshot,
    sha256_file,
    write_manifest_atomic,
)
from aether_re.evidence_store import EvidenceStore
from aether_re.intake import IntakeRequest, prepare_case
from aether_re.kernel_contracts import AuthorizationPolicy, EpistemicState, IntakeLimits
from aether_re.profile_router import route_case
from aether_re.checkpoint import write_checkpoint
from aether_re.cache import analysis_cache_key, verify_manifest
from aether_re.homologation import audit_run_package
from aether_re.lock import RunLock
from aether_re.contracts import validate_adapter_result
from aether_re.process import disk_budget_from_env, has_free_disk
from aether_re.static_profiles import select_static_profile
from aether_re.engines.native_normalize import normalize_native_structure
from aether_re.ir_graph import project_ir
from aether_re.ir import canonical_ir_dict
from aether_re.ir import IRDocument, IRLocation, IRNode
from aether_re.engines.reconstruct import build_reconstruction
from aether_re.profile_certification import certify_static_profile


LIMITATIONS_BASE = [
    "Pseudo-fonte NÃO é o código-fonte original (nomes, comentários e estrutura de ficheiros perdem-se na compilação).",
    "Otimizações do compilador, inlining e stripping reduzem a precisão da reconstrução.",
    "Binários packed/cifrados exigem unpack dinâmico antes da análise estática profunda.",
    "Análise completa de caixa-preta combina estática + dinâmica + emulação + contexto humano.",
]


@dataclass(frozen=True)
class CasePolicy:
    """Fail-closed policy for the universal orchestrator.

    Dynamic execution is never inferred from authorization.  It additionally
    requires an explicit VM policy and a materialized runtime proof.
    """

    authorization: AuthorizationPolicy
    intake_limits: IntakeLimits = field(default_factory=IntakeLimits)
    request_dynamic: bool = False
    lab_policy: dict[str, Any] | None = None
    runtime_proof: dict[str, Any] | None = None

    @classmethod
    def static_only(cls, principal: str = "local-owner") -> "CasePolicy":
        return cls(AuthorizationPolicy.from_dict({
            "schema": "authorization-policy.v1", "basis": "owner",
            "principal": principal, "scope": ["static-analysis"],
        }))

    @classmethod
    def dynamic(
        cls, principal: str = "local-owner", *, lab_policy: dict[str, Any] | None = None,
        runtime_proof: dict[str, Any] | None = None,
    ) -> "CasePolicy":
        return cls(AuthorizationPolicy.from_dict({
            "schema": "authorization-policy.v1", "basis": "owner",
            "principal": principal,
            "scope": ["static-analysis", "dynamic-execution"],
        }), request_dynamic=True, lab_policy=lab_policy, runtime_proof=runtime_proof)


@dataclass(frozen=True)
class CaseObservation:
    kind: str
    value: str
    epistemic_state: EpistemicState
    evidence_refs: tuple[str, ...] = ()
    confidence: float = 0.0
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class CaseReport:
    schema: str
    case_id: str
    target_sha256: str
    profile: str
    observations: tuple[CaseObservation, ...]
    graph: dict[str, Any]
    reconstruction: tuple[Any, ...]
    dynamic_status: str
    certification_status: str
    original_source_recovered: bool = False
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "case_id": self.case_id,
            "target_sha256": self.target_sha256, "profile": self.profile,
            "observations": [
                {**asdict(item), "epistemic_state": item.epistemic_state.value}
                for item in self.observations
            ],
            "graph": self.graph,
            "reconstruction": [
                {**asdict(item), "epistemic_state": item.epistemic_state.value}
                for item in self.reconstruction
            ],
            "dynamic_status": self.dynamic_status,
            "certification_status": self.certification_status,
            "original_source_recovered": self.original_source_recovered,
            "limitations": list(self.limitations),
        }


def run_profile_workers(intake: Any, decision: Any, policy: CasePolicy) -> tuple[CaseObservation, ...]:
    """Normalize routing evidence; external workers require separately pinned specs."""
    if not policy.authorization.allows("static-analysis"):
        raise ValueError("static_analysis_not_authorized")
    observations = []
    for candidate in decision.candidates:
        state = EpistemicState.EXACT if candidate.strength >= 90 else EpistemicState.UNKNOWN
        observations.append(CaseObservation(
            "profile-signature", candidate.profile_id, state,
            tuple(candidate.evidence),
            candidate.strength / 100.0,
        ))
    # This explicit UNKNOWN prevents profile detection from being promoted into
    # the impossible claim that original source was recovered.
    observations.append(CaseObservation(
        "original-source", "not-established", EpistemicState.UNKNOWN,
        limitations=("static evidence cannot recover original source identity",),
    ))
    return tuple(observations)


def normalize_observations(intake: Any, observations: tuple[CaseObservation, ...], profile: str) -> dict[str, Any]:
    nodes = tuple(
        IRNode(
            kind=item.kind, name=item.value,
            location=IRLocation("artifact", intake.root_artifact.artifact_id),
            source_backend="evidence-kernel", evidence_refs=item.evidence_refs,
            epistemic_state=item.epistemic_state, confidence=item.confidence,
            losses=item.limitations, attributes={},
        )
        for item in observations if item.evidence_refs
    )
    document = IRDocument("ir.v1", intake.root_artifact.artifact_id, profile, nodes, (), ())
    projection = project_ir(document)
    projection["abstentions"] = [
        {
            "kind": item.kind, "value": item.value,
            "epistemic_state": item.epistemic_state.value,
            "evidence_refs": list(item.evidence_refs),
            "losses": list(item.limitations) or ["evidence absent"],
        }
        for item in observations if not item.evidence_refs
    ]
    return {"document": document, "projection": projection}


def verify_reconstruction(intake: Any, graph: dict[str, Any], policy: CasePolicy) -> tuple[Any, ...]:
    # No function consensus is invented: unsupported bodies remain UNKNOWN.
    return build_reconstruction(graph["document"], [])


def certify_case(
    intake: Any, decision: Any, graph: dict[str, Any], reconstruction: tuple[Any, ...],
    policy: CasePolicy, observations: tuple[CaseObservation, ...], dynamic_status: str,
) -> CaseReport:
    certificate = certify_static_profile(
        {"schema": "profile-scope.v1", "profile_id": decision.profile_id},
        {}, {"workers": []}, {}, {"regressions": []},
    )
    certified = certificate["status"] == "QUITADA" and decision.epistemic_state is not EpistemicState.UNKNOWN
    return CaseReport(
        "universal-case-report.v1", intake.case_id, intake.root_artifact.sha256,
        decision.profile_id, observations, graph["projection"], reconstruction,
        dynamic_status, "certified" if certified else "abstained", False,
        tuple(decision.limitations) + (
            "profile certification denominator is not materialized for this case",
            "dynamic execution is disabled unless VM policy and runtime proof both verify",
        ),
    )


def _dynamic_gate(policy: CasePolicy, target_sha256: str) -> str:
    if not policy.request_dynamic:
        return "not_requested"
    if not policy.authorization.allows("dynamic-execution"):
        raise ValueError("dynamic_not_authorized")
    if policy.lab_policy is None or policy.runtime_proof is None:
        raise ValueError("dynamic_vm_proof_required")
    lab = policy.lab_policy
    proof = policy.runtime_proof
    required_lab = {
        "authorized": True, "isolation": "vm", "network_enabled": False,
        "writable_project_mount": False, "host_execution": False,
        "rollback_enabled": True, "collector_configured": True,
    }
    lab_valid = (
        isinstance(lab, dict)
        and all(lab.get(key) == value for key, value in required_lab.items())
        and isinstance(lab.get("snapshot_id"), str) and bool(lab["snapshot_id"].strip())
        and isinstance(lab.get("timeout_s"), int) and not isinstance(lab["timeout_s"], bool) and lab["timeout_s"] > 0
        and isinstance(lab.get("memory_limit_mb"), int) and not isinstance(lab["memory_limit_mb"], bool) and lab["memory_limit_mb"] > 0
    )
    proof_valid = (
        isinstance(lab, dict) and isinstance(proof, dict)
        and proof.get("schema") == "dynamic-lab-runtime-proof.v1"
        and proof.get("snapshot_id") == lab.get("snapshot_id")
        and proof.get("rollback_verified") is True
        and proof.get("network_isolated") is True
        and proof.get("collector_heartbeat") is True
        and isinstance(proof.get("events"), list) and bool(proof["events"])
    )
    if not lab_valid or not proof_valid:
        raise ValueError("dynamic_vm_proof_invalid")
    if proof.get("target_sha256") != target_sha256:
        raise ValueError("dynamic_target_mismatch")
    # There is no trusted VM executor in this repository.  Passing the gate is
    # not permission to fall back to host execution.
    return "eligible_no_executor"


def run_universal_case(target: Path, out_dir: Path, policy: CasePolicy) -> CaseReport:
    target, out_dir = Path(target).resolve(), Path(out_dir).resolve()
    if not isinstance(policy, CasePolicy):
        raise TypeError("case_policy_required")
    dynamic_status = _dynamic_gate(policy, sha256_file(target))
    intake = prepare_case(IntakeRequest(target, out_dir / "intake", policy.authorization, policy.intake_limits))
    store = EvidenceStore(intake.manifest_path.parent)
    decision = route_case(intake, store)
    observations = run_profile_workers(intake, decision, policy)
    graph = normalize_observations(intake, observations, decision.profile_id)
    reconstruction = verify_reconstruction(intake, graph, policy)
    report = certify_case(intake, decision, graph, reconstruction, policy, observations, dynamic_status)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "case_report.json"
    if report_path.exists():
        raise FileExistsError("case_report_already_exists")
    report_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def _adapter_status(name: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "available": bool(result.get("available", result.get("executed", result.get("ok")))),
        "executed": bool(result.get("executed")),
        "ok": bool(result.get("ok", False)),
        "produced_evidence": bool(result.get("produced_evidence")),
        "partial": bool(result.get("partial")),
        "error": result.get("error"),
        "mode": result.get("mode"),
        "report": result.get("report"),
        "decompiled_path": result.get("decompiled_path"),
        "returncode": result.get("returncode"),
    }


def _record_adapter_failure(report: AnalysisReport, key: str, error: str) -> None:
    report.adapter_results[key] = {
        "ok": False,
        "available": False,
        "executed": False,
        "produced_evidence": False,
        "partial": False,
        "error": error,
    }


def _native_function_evidence(native: dict[str, Any]) -> list[FunctionEvidence]:
    items: list[FunctionEvidence] = []
    sketches = native.get("function_sketches", [])
    for index, sketch in enumerate(sketches, start=1):
        imports_used = list(getattr(sketch, "imports_used", []))
        evidence = FunctionEvidence(
            address=f"native:{index}",
            name=str(getattr(sketch, "name", f"cluster_{index}")),
            source="native",
            confidence=float(getattr(sketch, "confidence", 0.3)),
            quality=0.35,
            coverage=0.2,
            calls=[imp.split("!", 1)[-1] for imp in imports_used],
            imports_used=imports_used,
            strings_near=list(getattr(sketch, "strings_near", [])),
            notes=str(getattr(sketch, "notes", "")),
            warnings=["Cluster semântico sem endereço real da função."],
            raw={"role_cluster": True},
        )
        items.append(evidence)
    return items


def _render_function_md(function: FunctionConsensus) -> list[str]:
    lines = [
        "",
        f"### `{function.address}` — `{function.name}`",
        "",
        f"- **Fontes:** {', '.join(function.sources)}",
        f"- **Confiança:** {function.confidence:.2f}",
        f"- **Qualidade da evidência:** {function.evidence_quality:.2f}",
        f"- **Concordância:** {function.source_agreement:.2f}",
        f"- **Cobertura do ensemble:** {function.coverage:.2f}",
        f"- **Fonte selecionada:** `{function.selected_source}`",
    ]
    if function.aliases:
        lines.append(f"- **Aliases:** {', '.join(f'`{name}`' for name in function.aliases)}")
    if function.calls:
        lines.append(f"- **Chamadas observadas:** {', '.join(f'`{call}`' for call in function.calls[:30])}")
    if function.imports_used:
        lines.append(f"- **Imports associados:** {', '.join(f'`{imp}`' for imp in function.imports_used[:15])}")
    if function.warnings:
        lines.append(f"- **Avisos:** {'; '.join(function.warnings[:5])}")
    if function.pseudocode:
        lines += ["", "```c", function.pseudocode[:18000], "```"]
    elif function.disassembly:
        lines += ["", "```text", function.disassembly[:18000], "```"]
    return lines


def _render_md(report: AnalysisReport) -> str:
    lines = [
        "# AetherRE Megazord Report",
        "",
        f"- **Target:** `{report.target}`",
        f"- **SHA256:** `{report.target_sha256}`",
        f"- **Type:** {report.file_type}",
        f"- **Size:** {report.size_bytes} bytes",
        f"- **Entropy:** {report.entropy:.4f}",
        f"- **Overall confidence:** {report.overall_confidence:.2f}",
        f"- **Function coverage:** {report.coverage.get('ensemble', {}).get('mean', 0.0):.2f}",
        f"- **Engines:** {', '.join(report.engines_used)}",
        "",
        "## Trust and coverage",
        "",
        "```json",
        json.dumps(report.coverage, indent=2, ensure_ascii=False, default=str),
        "```",
        "",
        "## Limitations",
    ]
    lines.extend(f"- {limitation}" for limitation in report.limitations)
    lines += ["", "## Findings"]
    for finding in report.findings:
        lines.append(
            f"- **[{finding.severity}/{finding.engine}]** {finding.title} "
            f"(conf={finding.confidence:.2f}): {finding.detail}"
        )
    lines += ["", "## Imports (top)"]
    lines.extend(f"- `{value}`" for value in report.imports[:50])
    lines += ["", "## Function consensus"]
    if report.merged_functions:
        for function in report.merged_functions:
            lines.extend(_render_function_md(function))
    else:
        lines.append("Nenhuma função endereçada foi produzida pelos adapters.")
    lines += [
        "",
        "## Adapter execution",
        "",
        "| Adapter | Available | Executed | Evidence | Partial | Status |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for name, result in report.adapter_results.items():
        if name.startswith("_"):
            continue
        lines.append(
            f"| {name} | {bool(result.get('available'))!s} | {bool(result.get('executed'))!s} | "
            f"{bool(result.get('produced_evidence'))!s} | {bool(result.get('partial'))!s} | "
            f"{('ok' if result.get('ok') else 'failed')} |"
        )
    lines += ["", "Pseudo-fonte completa: `pseudo_source.c`", "Índice por função: `ghidra_export/functions.json`"]
    return "\n".join(lines)


def adapters_status() -> list[dict[str, Any]]:
    return [
        GhidraAdapter().status(),
        RizinAdapter().status(),
        FridaAdapter().status(),
        UnicornAdapter().status(),
        AngrAdapter().status(),
        BinaryNinjaAdapter().status(),
        WasmAdapter().status(),
        AndroidAdapter().status(),
        JvmAdapter().status(),
        ILSpyAdapter().status(),
    ]


def run_megazord(
    target: Path,
    out_dir: Path | None = None,
    use_adapters: bool = True,
    deep: bool = True,
    profile_id: str | None = None,
) -> AnalysisReport:
    requested_target = Path(target)
    if _has_link_or_reparse_component(requested_target):
        raise ValueError("target_path_contains_link_or_reparse")
    if _is_hardlinked_regular_file(requested_target):
        raise ValueError("target_hardlink_not_allowed")
    if not requested_target.is_file():
        raise FileNotFoundError(requested_target)
    target = requested_target.resolve()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    requested_out_dir = Path(out_dir) if out_dir is not None else Path("output") / f"{target.stem}_{stamp}"
    if _has_link_or_reparse_component(requested_out_dir):
        raise ValueError("output_path_contains_link_or_reparse")
    out_dir = requested_out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    run_lock = RunLock(out_dir / "run.lock")
    run_lock.acquire()
    atexit.register(run_lock.release)
    checkpoint_path = out_dir / "checkpoint.json"
    current_stage = {"value": "initializing"}
    finished = {"value": False}
    failure_recorded = {"value": False}
    initial_target_sha256 = sha256_file(target)
    cache_key = analysis_cache_key(target, config={"deep": deep, "use_adapters": use_adapters, "profile_id": profile_id})
    def checkpoint(stage: str, status: str = "running", **extra: Any) -> None:
        current_stage["value"] = stage
        write_checkpoint(
            checkpoint_path,
            {"schema": "analysis-checkpoint.v1", "status": status, "stage": stage, "target": str(target), "cache_key": cache_key, **extra},
        )

    def mark_failed_on_exit() -> None:
        if not finished["value"] and not failure_recorded["value"]:
            try:
                checkpoint("failed", status="failed", error="analysis exited before final publication")
            except Exception:
                pass

    atexit.register(mark_failed_on_exit)

    checkpoint("intake")

    minimum_free_mb = disk_budget_from_env("AETHER_MIN_FREE_MB", 128)
    if not has_free_disk(out_dir, minimum_free_mb):
        failure_recorded["value"] = True
        checkpoint("failed", status="failed", error="insufficient_disk_space", minimum_free_mb=minimum_free_mb)
        run_lock.release()
        raise OSError(f"insufficient_disk_space:{minimum_free_mb}MiB")

    # Kernel intake snapshots authorized bytes into an immutable object store.
    policy = AuthorizationPolicy.from_dict({"schema": "authorization-policy.v1", "basis": "owner", "principal": "local-cli", "scope": ["static-analysis"]})
    try:
        intake = prepare_case(IntakeRequest(target, out_dir / "intake", policy, IntakeLimits(max_file_bytes=512 * 1024 * 1024)))
        store = EvidenceStore(intake.manifest_path.parent)
        analysis_target = store.resolve(intake.root_artifact)
        snapshot_sha256 = intake.root_artifact.sha256
        decision = route_case(intake, store)
        snapshot_path = out_dir / "input.snapshot"
        if snapshot_path.exists() or snapshot_path.is_symlink():
            raise FileExistsError("input_snapshot_already_exists")
        create_verified_snapshot(
            analysis_target,
            snapshot_path,
            expected_sha256=snapshot_sha256,
            max_bytes=512 * 1024 * 1024,
        )
    except Exception as exc:
        failure_recorded["value"] = True
        checkpoint("failed", status="failed", error=str(exc))
        run_lock.release()
        raise

    selected_profile = select_static_profile(analysis_target, profile_id)
    report = AnalysisReport(target=str(target))
    report.profile = {"profile_id": selected_profile.profile_id, "confidence": selected_profile.confidence, "reasons": list(selected_profile.reasons), "candidates": list(selected_profile.candidates)}
    report.limitations = list(LIMITATIONS_BASE)
    report.case_id = intake.case_id
    report.intake_manifest = str(intake.manifest_path)
    report.root_artifact_id = intake.root_artifact.artifact_id
    report.profile_decision = decision.to_dict()
    report.evidence_journal = str(intake.journal_path)

    triage_result = triage.run_triage(analysis_target)
    report.target_sha256 = triage_result["sha256"]
    report.size_bytes = triage_result["size"]
    report.entropy = triage_result["entropy"]
    report.file_type = triage_result["file_type"]
    report.findings.extend(triage_result["findings"])
    report.engines_used.append("triage")
    raw: bytes = triage_result["raw"]
    checkpoint("triage", target_sha256=report.target_sha256)

    structure = pe_elf.run_structure(raw)
    structure.setdefault("parse_status", "complete" if selected_profile.profile_id in {"native-pe", "native-elf"} else "invalid")
    structure.setdefault("parse_errors", [])
    if selected_profile.profile_id in {"native-pe", "native-elf"}:
        normalized_ir = normalize_native_structure(f"sha256:{snapshot_sha256}", selected_profile.profile_id, structure, f"sha256:{snapshot_sha256}#structure")
        report.ir = canonical_ir_dict(normalized_ir)
        (out_dir / "ir.json").write_text(json.dumps(report.ir, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        (out_dir / "ir_graph.json").write_text(json.dumps(project_ir(normalized_ir), ensure_ascii=False, sort_keys=True), encoding="utf-8")
    report.imports = structure.get("imports", [])
    report.exports = structure.get("exports", [])
    report.sections = structure.get("sections", [])
    report.segments = structure.get("segments", [])
    report.symbols = structure.get("symbols", [])
    report.relocations = structure.get("relocations", [])
    report.needed_libraries = structure.get("needed_libraries", [])
    report.findings.extend(structure.get("findings", []))
    report.engines_used.append("structure")
    is_64 = bool(structure.get("is_64", True))
    file_format = structure.get("format", report.file_type)
    entry = structure.get("entry_point", "")
    machine = int(structure.get("machine", 0) or 0)
    architecture = {
        0x8664: "x86_64",
        0x14C: "x86",
        0xAA64: "arm64",
        0x1C0: "arm",
        # ELF e_machine values (kept explicit instead of assuming x86).
        3: "i386",
        8: "mips",
        40: "arm",
        62: "x86_64",
        183: "aarch64",
        243: "riscv",
    }.get(machine, structure.get("machine_name", "unknown"))
    report.target_identity = {
        "sha256": report.target_sha256,
        "module": target.name,
        "format": file_format,
        "architecture": architecture,
        "entry_point": entry,
        "image_base": structure.get("image_base", ""),
        "image_base_kind": structure.get("image_base_kind", "unknown"),
        "machine": machine,
    }
    # Qualify every observed symbol with the artifact module and address
    # space.  A name alone is never treated as a function equivalence proof.
    image_base_text = str(structure.get("image_base", ""))
    try:
        image_base_int = int(image_base_text, 0)
    except (TypeError, ValueError):
        image_base_int = None
    for symbol in report.symbols:
        if not isinstance(symbol, dict):
            continue
        name = str(symbol.get("name") or "")
        value_text = str(symbol.get("value") or "")
        address_space = str(symbol.get("address_space") or ("preferred_rva" if str(file_format).upper().startswith("PE") else "preferred_vaddr"))
        rva_text = str(symbol.get("rva") or "")
        if not rva_text and value_text:
            try:
                value_int = int(value_text, 0)
            except (TypeError, ValueError):
                value_int = None
            if value_int is not None:
                if address_space.endswith("rva"):
                    rva_text = hex(value_int)
                elif image_base_int is not None and value_int >= image_base_int:
                    rva_text = hex(value_int - image_base_int)
        symbol["module"] = target.name
        symbol["rva"] = rva_text
        symbol["qualified_identity"] = f"{target.name}!{address_space}:{rva_text or value_text}:{name}"
    checkpoint("structure", target_sha256=report.target_sha256)

    if str(file_format).upper().startswith("ELF"):
        report.dwarf = dwarf.analyze_dwarf(analysis_target)
        report.engines_used.append("dwarf")
        if report.dwarf.get("status") in {"partial", "invalid"}:
            report.limitations.append("leitura DWARF parcial ou inválida; sem promoção automática de símbolos")

    strings_result = strings_decode.run_strings_decode(raw)
    report.strings = strings_result.get("strings", [])
    report.decoded_payloads = strings_result.get("decoded_payloads", [])
    report.findings.extend(strings_result.get("findings", []))
    report.engines_used.append("strings_decode")
    checkpoint("strings_decode", target_sha256=report.target_sha256)

    if deep:
        disasm_result = disasm.run_disasm(raw, is_64=is_64, file_format=file_format)
        report.disassembly_snippets = disasm_result.get("snippets", [])
        report.findings.extend(disasm_result.get("findings", []))
        report.engines_used.append("disasm")

    reconstruct_result = reconstruct.run_reconstruct(
        target_name=target.name,
        file_format=file_format,
        entry_point=entry,
        imports=report.imports,
        exports=report.exports,
        sections=report.sections,
        strings=report.strings,
        decoded=report.decoded_payloads,
        disasm_snippets=report.disassembly_snippets,
    )
    report.function_sketches = reconstruct_result["function_sketches"]
    report.pseudo_source = reconstruct_result["pseudo_source"]
    report.findings.extend(reconstruct_result["findings"])
    report.engines_used.append("reconstruct")
    checkpoint("reconstruct", target_sha256=report.target_sha256)

    adapter_results: dict[str, dict[str, Any]] = {}
    if use_adapters:
        # Do not run every parser against every artifact.  Profile routing is a
        # security boundary: specialized workers only see formats they declare
        # they understand, and unsupported profiles abstain rather than falling
        # through to native reconstruction.
        native_profiles = {'native-pe', 'native-elf'}
        adapters: list[Any] = ([GhidraAdapter(), RizinAdapter(), FridaAdapter(), UnicornAdapter(), AngrAdapter(), BinaryNinjaAdapter()]
                                if selected_profile.profile_id in native_profiles else [])
        profile_workers: dict[str, list[Any]] = {
            'wasm': [WasmAdapter()],
            'android-apk': [AndroidAdapter()],
            'jvm': [JvmAdapter()],
            'dotnet': [ILSpyAdapter()],
            # Rizin is the existing, hash-recorded static backend for Mach-O.
            # It is explicitly routed here instead of relying on native PE/ELF
            # fallback, preserving profile provenance in the report.
            'macho': [RizinAdapter()],
        }
        adapters.extend(profile_workers.get(selected_profile.profile_id, []))
        for adapter in adapters:
            key = adapter.name
            if adapter.available():
                try:
                    result = adapter.analyze(analysis_target, out_dir)
                    result["available"] = True
                    result = validate_adapter_result(key, result)
                    adapter_results[key] = result
                    report.engines_used.append(f"adapter:{key}")
                except Exception as exc:
                    adapter_results[key] = validate_adapter_result(key, {
                        "schema": "adapter-result.v1",
                        "state": "failed",
                        "ok": False,
                        "available": True,
                        "executed": True,
                        "produced_evidence": False,
                        "partial": False,
                        "error": str(exc),
                    })
            else:
                adapter_results[key] = validate_adapter_result(key, {
                    "schema": "adapter-result.v1",
                    "state": "unavailable",
                    "ok": False,
                    "available": False,
                    "executed": False,
                    "produced_evidence": False,
                    "partial": False,
                    "error": f"{key} não instalado ou indisponível",
                })

        checkpoint("adapters", target_sha256=report.target_sha256)

    ghidra_result = adapter_results.get("ghidra", {})
    rizin_result = adapter_results.get("rizin", {})
    angr_result = adapter_results.get("angr", {})
    binaryninja_result = adapter_results.get("binaryninja", {})
    native_evidence = _native_function_evidence(reconstruct_result)
    successful_sources: list[str] = []
    for name, result in adapter_results.items():
        if result.get("produced_evidence") is not True:
            continue
        if name == "ghidra":
            if ghidra_result_is_complete(result):
                successful_sources.append(name)
        elif result.get("partial") is False:
            successful_sources.append(name)
    if (
        angr_result.get("produced_evidence") is True
        and angr_result.get("partial") is False
        and angr_result.get("functions")
    ):
        successful_sources.append("angr")

    # Get base address for address normalization
    base_addr = 0
    if structure.get("image_base"):
        try:
            base_addr = int(structure["image_base"], 16) if isinstance(structure["image_base"], str) else structure["image_base"]
        except (ValueError, TypeError):
            pass

    evidence_items = [*native_evidence]
    if ghidra_result.get("decompiled_path") and Path(ghidra_result["decompiled_path"]).is_file():
        from aether_re.engines.ghidra_parse import parse_decompiled_file

        function_dicts = parse_decompiled_file(Path(ghidra_result["decompiled_path"]))
        ghidra_complete = ghidra_result_is_complete(ghidra_result)
        if not ghidra_complete:
            function_dicts = mark_ghidra_functions_partial(function_dicts)
            report.limitations.append(
                "Ghidra output is partial or lacks an explicit complete summary; "
                "it is retained as evidence but not selected as complete pseudo-source."
            )
        evidence_items.extend(FunctionEvidence.from_mapping(item) for item in function_dicts)
        write_function_index(function_dicts, out_dir / "ghidra_export" / "functions.json")
    if angr_result.get("functions"):
        evidence_items.extend(
            FunctionEvidence.from_mapping(item) for item in angr_result["functions"]
        )
    if rizin_result.get("functions"):
        evidence_items.extend(
            FunctionEvidence.from_mapping(item) for item in rizin_result["functions"]
        )
    if binaryninja_result.get("functions"):
        evidence_items.extend(FunctionEvidence.from_mapping(item) for item in binaryninja_result["functions"])

    merged_functions = merge_function_evidence(
        evidence_items,
        successful_sources=list(dict.fromkeys(successful_sources or ["native"])),
        base_addr=base_addr,
    )
    if ghidra_result.get("decompiled_path") and not ghidra_result_is_complete(ghidra_result):
        for function in merged_functions:
            if function.sources == ["ghidra"]:
                function.confidence = min(function.confidence, GHIDRA_PARTIAL_CONFIDENCE_CAP)
                warning = "Ghidra export is partial; single-source confidence is capped at 0.80."
                if warning not in function.warnings:
                    function.warnings.append(warning)
    report.function_evidence = evidence_items
    report.merged_functions = merged_functions
    successful_sources = list(dict.fromkeys(successful_sources))
    if angr_result.get("produced_evidence") is True and angr_result.get("partial") is False:
        successful_sources = list(dict.fromkeys([*successful_sources, "angr"]))
    failed_sources = [
        name for name, result in adapter_results.items() if not result.get("ok", False)
    ]
    report.overall_confidence, report.confidence_rationale = compute_overall_confidence(
        merged_functions,
        native_confidence=float(reconstruct_result.get("confidence", 0.5)),
        successful_sources=successful_sources,
        failed_sources=failed_sources,
    )
    if (
        ghidra_result.get("decompiled_path")
        and not ghidra_result_is_complete(ghidra_result)
        and not successful_sources
    ):
        report.overall_confidence = min(
            report.overall_confidence, GHIDRA_PARTIAL_CONFIDENCE_CAP
        )
    report.coverage = {
        "ensemble": {
            "functions": len(merged_functions),
            "mean": sum(item.coverage for item in merged_functions) / len(merged_functions)
            if merged_functions
            else 0.0,
            "mean_confidence": sum(item.confidence for item in merged_functions) / len(merged_functions)
            if merged_functions
            else 0.0,
        },
        "sources": {
            name: {
                "available": bool(result.get("available")),
                "executed": bool(result.get("executed")),
                "produced_evidence": bool(result.get("produced_evidence")),
                "partial": bool(result.get("partial")),
            }
            for name, result in adapter_results.items()
        },
    }
    report.adapter_results = adapter_results
    report.adapter_results["_output_dir"] = str(out_dir)

    decompilation = merge_decompilation_results(
        ghidra_result if ghidra_result else None,
        rizin_result if rizin_result else None,
        reconstruct_result,
        angr_result if angr_result else None,
    )
    if decompilation.get("best_source") == "ghidra":
        ghidra_text = Path(ghidra_result["decompiled_path"]).read_text(
            encoding="utf-8", errors="replace"
        )
        report.pseudo_source = (
            "/* === GHIDRA DECOMPILATION (preferida) === */\n"
            + ghidra_text
            + "\n\n/* === MEGAZORD SEMANTIC SKELETON (context) === */\n"
            + report.pseudo_source
        )
    # Canonicalize line endings so JSON and the materialized source are identical.
    report.pseudo_source = report.pseudo_source.replace("\r\n", "\n").replace("\r", "\n")
    # write_bytes avoids platform newline translation and makes the hashable artifact exact.
    (out_dir / "pseudo_source.c").write_bytes(report.pseudo_source.encode("utf-8"))
    (out_dir / "findings.md").write_text(_render_md(report), encoding="utf-8")
    (out_dir / "strings.txt").write_text(
        "\n".join(report.strings), encoding="utf-8", errors="replace"
    )

    # Gerar relatórios comparativos
    comparative_dir = out_dir / "comparative"
    generate_comparative_report(report, comparative_dir)

    # O alvo pode ter sido trocado enquanto adapters externos executavam.
    # Nunca publique relatório/manifesto que misture bytes diferentes.
    final_target_sha256 = sha256_file(target)
    if final_target_sha256 != initial_target_sha256 or report.target_sha256 != snapshot_sha256:
        failure_recorded["value"] = True
        checkpoint(
            "failed",
            status="failed",
            target_sha256=report.target_sha256,
            error="target_changed_during_analysis",
            observed_target_sha256=final_target_sha256,
        )
        run_lock.release()
        raise RuntimeError("target_changed_during_analysis")

    # Persist only after every derived artifact and metric is final.
    (out_dir / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    checkpoint("persisted", status="succeeded", target_sha256=report.target_sha256)
    write_manifest_atomic(
        build_manifest(
            target,
            out_dir,
            metadata={"target_sha256": report.target_sha256, "engines_used": report.engines_used, "cache_key": cache_key},
        ),
        out_dir / "manifest.json",
    )

    # A successful producer return is not evidence of a valid package. Verify
    # the bytes after publication and audit the whole package while this run
    # still owns run.lock, preventing a cooperating concurrent run from changing
    # the package during verification.
    manifest_ok, manifest_errors = verify_manifest(
        out_dir / "manifest.json", target, expected_cache_key=cache_key
    )
    if not manifest_ok:
        failure_recorded["value"] = True
        checkpoint(
            "failed",
            status="failed",
            error="published_manifest_invalid",
            manifest_errors=manifest_errors,
        )
        run_lock.release()
        raise RuntimeError("published_manifest_invalid")

    try:
        package_audit = audit_run_package(out_dir, target=target, active_lock=run_lock)
    except Exception as exc:
        failure_recorded["value"] = True
        checkpoint(
            "failed",
            status="failed",
            error="published_package_audit_error",
            audit_error=type(exc).__name__,
        )
        run_lock.release()
        raise RuntimeError("published_package_audit_error") from exc
    if package_audit.get("status") != "pass":
        failure_recorded["value"] = True
        checkpoint(
            "failed",
            status="failed",
            error="published_package_invalid",
            audit_issues=package_audit.get("issues", []),
        )
        run_lock.release()
        raise RuntimeError("published_package_invalid")

    try:
        lock_released = run_lock.release()
    except Exception as exc:
        failure_recorded["value"] = True
        checkpoint(
            "failed",
            status="failed",
            target_sha256=report.target_sha256,
            error="run_lock_release_failed",
            release_error=type(exc).__name__,
        )
        raise RuntimeError("run_lock_release_failed") from exc
    if not lock_released:
        failure_recorded["value"] = True
        checkpoint(
            "failed",
            status="failed",
            target_sha256=report.target_sha256,
            error="run_lock_release_failed",
            release_error="owner_mismatch_or_lock_still_present",
        )
        raise RuntimeError("run_lock_release_failed")
    finished["value"] = True

    return report
