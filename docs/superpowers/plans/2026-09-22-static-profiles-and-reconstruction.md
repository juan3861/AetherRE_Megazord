# Static Profiles and Reconstruction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the current PE/ELF-centric static pipeline into a provenance-preserving normalized IR, multi-backend reconstruction system, and separately certifiable native, .NET, Android, WebAssembly, Mach-O, JVM, and firmware profiles.

**Architecture:** Preserve `AnalysisReport` as the publication boundary while adding an immutable canonical IR between adapter output and consensus. Profile detection selects an explicit, bounded set of out-of-process workers; every worker result is normalized to IR with losses and evidence references before graph projection, consensus, reconstruction, or certification. No profile is promoted merely because a tool recognizes the file.

**Tech Stack:** Python 3.11+, dataclasses, JSON, SQLite graph store, pytest, existing `run_bounded`, Ghidra, Rizin, angr, optional RetDec, ILSpy, JADX, Apktool, WABT, Binaryen, and profile-specific fixtures.

**Spec:** `docs/superpowers/specs/2026-09-22-universal-forensic-reconstruction-design.md`

## Global Constraints

- Preserve the epistemic states exactly as `EXACT`, `VERIFIED_RECONSTRUCTION`, `PROBABILISTIC_INFERENCE`, `HYPOTHESIS`, and `UNKNOWN`.
- Prefer `UNKNOWN` to an unsupported conclusion; generated pseudocode is never described as original source.
- Every normalized node and edge carries `source_backend`, non-empty `evidence_refs`, a location, `EpistemicState` imported from `aether_re.kernel_contracts`, confidence, and declared `losses`; JSON serialization uses `.value`.
- External analyzers execute out of process through `aether_re.process.run_bounded`; shell execution, target execution, and network access are forbidden in this static plan.
- Every external tool is identified by executable SHA-256, version output, license identifier, invocation, and worker policy before it may produce certifying evidence.
- GPL/LGPL tools remain separate processes; no external source is copied into this repository without separately recorded provenance and license approval.
- Existing Ghidra, Rizin, angr, Binary Ninja, PE/ELF, evidence, custody, checkpoint, and manifest behavior must remain green.
- A missing tool yields `unavailable`; malformed output yields `failed`; bounded partial output yields `partial`; none of these states can become successful evidence silently.
- Certification is profile-specific and fail-closed. Detection, adapter availability, and a green unit test do not constitute certification.
- Each task starts with a failing test, applies the smallest implementation that satisfies the contract, runs focused and regression tests, and commits only its declared files.

## File Structure

### Canonical core

- Create `aether_re/ir.py`: immutable IR value types, validators, canonical serialization, deterministic identity, and loss preservation.
- Create `aether_re/ir_graph.py`: deterministic projection from IR documents into the existing graph-store input schema.
- Create `aether_re/static_profiles.py`: content-based profile detection, profile declarations, backend selection, and certification boundaries.
- Create `aether_re/static_worker.py`: pinned-tool probe and bounded, non-shell worker invocation built on `run_bounded`.
- Modify `aether_re/models.py`: publish canonical IR and profile fields without deleting current report fields.
- Modify `aether_re/contracts.py`: add strict static-worker result validation while retaining `adapter-result.v1` compatibility.

### Native and reconstruction

- Create `aether_re/engines/native_normalize.py`: PE/ELF structures and adapter functions to canonical IR.
- Modify `aether_re/engines/pe_elf.py`: expose parse completeness and explicit losses required by normalization.
- Modify `aether_re/engines/consensus.py`: replace fixed universal weights with profile/backend reliability and conflict-preserving consensus.
- Modify `aether_re/engines/reconstruct.py`: render reconstruction units with epistemic labels and evidence citations.
- Modify `aether_re/pipeline.py`: route by profile, execute only selected workers, normalize before consensus, and publish IR/graph/reconstruction artifacts.

### Profile adapters

- Create `aether_re/adapters/ilspy.py`: `.NET` worker and ILSpy JSON/text normalization.
- Create `aether_re/adapters/android.py`: APK/DEX worker coordination for JADX and Apktool.
- Create `aether_re/adapters/wasm.py`: WABT/Binaryen worker coordination and WebAssembly normalization.
- Create `aether_re/adapters/macho.py`: Mach-O normalization using Rizin/Ghidra outputs.
- Create `aether_re/adapters/jvm.py`: JAR/class normalization through a pinned decompiler worker.
- Create `aether_re/adapters/firmware.py`: raw/Intel HEX/container observations without executing extracted content.
- Modify `aether_re/adapters/__init__.py`: export the new adapters.

### Certification and operator surface

- Create `aether_re/profile_certification.py`: validate corpus identity, tool pins, measured entities/relations, regression, limitations, and certification state.
- Create `tools/static_workers.lock.json`: reviewed executable/version/hash/license records; values are generated by the probe command and rejected if any required field is absent.
- Create `docs/static-profile-matrix.md`: exact formats, architectures, workers, licenses, measured relations, exclusions, and certification states.
- Modify `megazord.py`: add `profile-probe`, `profile-certify`, and `--profile` for `analyze`.

### Tests and fixtures

- Create `tests/test_ir.py`, `tests/test_ir_graph.py`, `tests/test_static_profiles.py`, `tests/test_static_worker.py`, `tests/test_native_normalize.py`, `tests/test_consensus_calibrated.py`, `tests/test_reconstruction_provenance.py`.
- Create `tests/test_adapter_ilspy.py`, `tests/test_adapter_android.py`, `tests/test_adapter_wasm.py`, `tests/test_adapter_macho.py`, `tests/test_adapter_jvm.py`, `tests/test_adapter_firmware.py`.
- Create `tests/test_profile_certification.py` and `tests/test_static_profile_cli.py`.
- Create only tiny, redistributable fixtures under `tests/fixtures/static_profiles/`; every binary fixture has `source/`, `oracle.json`, `LICENSE.txt`, and `SHA256SUMS`.

## Review Focus

- Ambiguous ZIP containers (`.jar`, `.apk`, generic ZIP): classification must inspect entries safely, return all candidates, and remain `UNKNOWN` on unresolved ambiguity; Task 3 pins this.
- Adapter output with addresses from mixed spaces (file offset, RVA, VA, IL offset, WASM function index): normalization must not merge them merely because numeric values match; Tasks 1 and 5 pin this.
- A worker executable changed after probing: analysis must fail before launch on hash mismatch; Task 4 pins this.
- A backend omits fields or emits unknown schema versions: normalization must preserve raw evidence, declare losses, and refuse certifying status; Tasks 2 and 11 pin this.
- A profile has excellent entity precision but no measured relations or independent oracle: certification must remain `NAO_COMPROVADA`; Task 11 pins this.

---

### Task 1: Canonical IR value model and identity

**Files:**
- Create: `aether_re/ir.py`
- Modify: `aether_re/models.py`
- Test: `tests/test_ir.py`

**Interfaces:**
- Consumes: evidence identifiers already emitted by the evidence kernel as strings.
- Produces: `IRLocation`, `IRNode`, `IREdge`, `IRDocument`, `validate_ir(document: IRDocument) -> None`, and `canonical_ir_dict(document: IRDocument) -> dict[str, Any]`.

- [ ] **Step 1: Write the failing identity, address-space, provenance, and loss tests**

```python
from dataclasses import replace
import pytest

from aether_re.ir import IREdge, IRDocument, IRLocation, IRNode, canonical_ir_dict, validate_ir
from aether_re.kernel_contracts import EpistemicState


def node(space: str, value: str) -> IRNode:
    return IRNode(
        kind="function", name="parse", location=IRLocation(space=space, value=value),
        source_backend="fixture", evidence_refs=("sha256:abc#functions/0",),
        epistemic_state=EpistemicState.EXACT, confidence=1.0, losses=(), attributes={"signature": "int parse(void)"},
    )


def test_ir_identity_separates_equal_numbers_in_different_address_spaces():
    assert node("pe:rva", "0x1000").identity != node("dotnet:il", "0x1000").identity


def test_ir_validation_rejects_unproven_node_and_dangling_edge():
    bad = replace(node("pe:rva", "0x1000"), evidence_refs=())
    with pytest.raises(ValueError, match="ir_evidence_refs_required"):
        validate_ir(IRDocument("ir.v1", "artifact", "native-pe", (bad,), (), ()))
    edge = IREdge("calls", node("pe:rva", "0x1000").identity, "missing", "fixture", ("sha256:abc#calls/0",), "EXACT", 1.0, (), {})
    with pytest.raises(ValueError, match="ir_edge_endpoint_missing"):
        validate_ir(IRDocument("ir.v1", "artifact", "native-pe", (node("pe:rva", "0x1000"),), (edge,), ()))


def test_ir_serialization_is_deterministic_and_preserves_losses():
    item = replace(node("wasm:function", "7"), losses=("local_variable_names",))
    document = IRDocument("ir.v1", "artifact", "wasm", (item,), (), ("source_comments",))
    assert canonical_ir_dict(document)["nodes"][0]["losses"] == ["local_variable_names"]
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `python -m pytest tests/test_ir.py -q`

Expected: collection fails with `ModuleNotFoundError: No module named 'aether_re.ir'`.

- [ ] **Step 3: Implement the immutable IR contracts**

```python
from aether_re.kernel_contracts import EpistemicState

@dataclass(frozen=True)
class IRLocation:
    space: str
    value: str
    module: str = ""

@dataclass(frozen=True)
class IRNode:
    kind: str
    name: str
    location: IRLocation
    source_backend: str
    evidence_refs: tuple[str, ...]
    epistemic_state: EpistemicState
    confidence: float
    losses: tuple[str, ...]
    attributes: Mapping[str, Any]

    @property
    def identity(self) -> str:
        payload = f"{self.kind}\0{self.location.space}\0{self.location.value}\0{self.location.module}\0{self.name}"
        return "irn:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

@dataclass(frozen=True)
class IREdge:
    kind: str
    source: str
    target: str
    source_backend: str
    evidence_refs: tuple[str, ...]
    epistemic_state: EpistemicState
    confidence: float
    losses: tuple[str, ...]
    attributes: Mapping[str, Any]

@dataclass(frozen=True)
class IRDocument:
    schema: str
    artifact_id: str
    profile_id: str
    nodes: tuple[IRNode, ...]
    edges: tuple[IREdge, ...]
    losses: tuple[str, ...]
```

Validate `EpistemicState`, finite confidence in `[0.0, 1.0]`, reject duplicate node identities, reject dangling edges, sort nodes by identity and edges by `(kind, source, target, source_backend)` in `canonical_ir_dict`, serialize the enum with `.value`, and add `ir: dict[str, Any]` plus `profile: dict[str, Any]` fields to `AnalysisReport`.

- [ ] **Step 4: Run focused and model regressions**

Run: `python -m pytest tests/test_ir.py tests/test_ensemble.py tests/test_identity.py -q`

Expected: all tests pass; existing `AnalysisReport.to_dict()` remains JSON-serializable.

- [ ] **Step 5: Commit the IR contract**

```bash
git add aether_re/ir.py aether_re/models.py tests/test_ir.py
git commit -m "feat(ir): add provenance-preserving canonical model"
```

#### Task 1B: Deterministic IR graph projection

**Files:**
- Create: `aether_re/ir_graph.py`
- Modify: `aether_re/graph_store.py:116-241`
- Test: `tests/test_ir_graph.py`
- Test: `tests/test_graph_store.py`

**Interfaces:**
- Consumes: `IRDocument` and `canonical_ir_dict` from Task 1.
- Produces: `project_ir(document: IRDocument) -> dict[str, Any]` compatible with the existing `ingest_graph(db_path: Path, document: Any, *, run_id: str, max_nodes: int = 100_000, max_edges: int = 300_000) -> dict[str, Any]`.

- [ ] **Step 1: Write failing projection tests**

```python
from aether_re.ir import IREdge, IRDocument, IRLocation, IRNode
from aether_re.ir_graph import project_ir


def test_projection_preserves_backend_evidence_state_and_losses():
    left = IRNode("function", "a", IRLocation("elf:vaddr", "0x10"), "rizin", ("ev:a",), "EXACT", 1.0, (), {})
    right = IRNode("function", "b", IRLocation("elf:vaddr", "0x20"), "ghidra", ("ev:b",), "PROBABILISTIC_INFERENCE", .7, ("types",), {})
    edge = IREdge("calls", left.identity, right.identity, "rizin", ("ev:c",), "EXACT", 1.0, (), {})
    graph = project_ir(IRDocument("ir.v1", "sha256:x", "native-elf", (right, left), (edge,), ()))
    assert [n["id"] for n in graph["nodes"]] == sorted(n["id"] for n in graph["nodes"])
    assert graph["edges"][0]["evidence_refs"] == ["ev:c"]
    assert graph["nodes"][1]["losses"] == ["types"]
```

Add a second test that attempts to project schema `ir.v2` and expects `ValueError("ir_schema_unsupported")` before the graph database is opened.

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `python -m pytest tests/test_ir_graph.py -q`

Expected: import failure for `aether_re.ir_graph`.

- [ ] **Step 3: Implement a strict projection boundary**

```python
def project_ir(document: IRDocument) -> dict[str, Any]:
    validate_ir(document)
    if document.schema != "ir.v1":
        raise ValueError("ir_schema_unsupported")
    nodes = [{
        "id": item.identity, "kind": item.kind, "name": item.name,
        "location": asdict(item.location), "source_backend": item.source_backend,
        "evidence_refs": list(item.evidence_refs), "epistemic_state": item.epistemic_state,
        "confidence": item.confidence, "losses": list(item.losses), "attributes": dict(item.attributes),
    } for item in document.nodes]
    edges = [{
        "source": item.source, "target": item.target, "kind": item.kind,
        "source_backend": item.source_backend, "evidence_refs": list(item.evidence_refs),
        "epistemic_state": item.epistemic_state, "confidence": item.confidence,
        "losses": list(item.losses), "attributes": dict(item.attributes),
    } for item in document.edges]
    return {"schema": "forensic-graph.v2", "artifact_id": document.artifact_id,
            "profile_id": document.profile_id, "nodes": sorted(nodes, key=lambda x: x["id"]),
            "edges": sorted(edges, key=lambda x: (x["kind"], x["source"], x["target"], x["source_backend"])),
            "losses": sorted(document.losses)}
```

Extend `_normalise_graph` only enough to accept `forensic-graph.v2` fields without dropping them. Keep v1 readers working and reject collisions where identical IDs carry different payloads.

- [ ] **Step 4: Run focused and graph-store regressions**

Run: `python -m pytest tests/test_ir_graph.py tests/test_graph_store.py -q`

Expected: all tests pass, including tamper and atomic-conflict tests.

- [ ] **Step 5: Commit the graph projection**

```bash
git add aether_re/ir_graph.py aether_re/graph_store.py tests/test_ir_graph.py tests/test_graph_store.py
git commit -m "feat(graph): project canonical IR without provenance loss"
```

### Task 2: Content-based profiles and pinned static workers

This task has two independently reviewable subcycles: content routing first, then the worker/license boundary. Both must pass before any format adapter begins.

**Files:**
- Create: `aether_re/static_profiles.py`
- Modify: `aether_re/engines/triage.py:15-56`
- Test: `tests/test_static_profiles.py`

**Interfaces:**
- Consumes: a target `Path`, at most 1 MiB of header/container metadata, and an optional requested profile.
- Produces: `ProfileMatch`, `detect_static_profiles(target: Path) -> tuple[ProfileMatch, ...]`, and `select_static_profile(target: Path, requested: str | None = None) -> ProfileMatch`.

- [ ] **Step 1: Write failing classifier tests including ambiguous ZIP review focus**

```python
import zipfile
import pytest
from aether_re.static_profiles import detect_static_profiles, select_static_profile


def test_apk_detection_uses_entries_not_extension(tmp_path):
    target = tmp_path / "sample.bin"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("classes.dex", b"dex\n035\0")
    assert detect_static_profiles(target)[0].profile_id == "android-apk"


def test_ambiguous_zip_abstains(tmp_path):
    target = tmp_path / "mixed.zip"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\0")
        zf.writestr("A.class", b"\xca\xfe\xba\xbe")
    with pytest.raises(ValueError, match="profile_ambiguous"):
        select_static_profile(target)


def test_requested_profile_must_match_content(elf_fixture):
    with pytest.raises(ValueError, match="requested_profile_mismatch"):
        select_static_profile(elf_fixture, "dotnet")
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `python -m pytest tests/test_static_profiles.py -q`

Expected: import failure for `aether_re.static_profiles`.

- [ ] **Step 3: Implement declarations and bounded classifiers**

```python
@dataclass(frozen=True)
class ProfileDeclaration:
    profile_id: str
    formats: tuple[str, ...]
    address_spaces: tuple[str, ...]
    backend_names: tuple[str, ...]
    static_only: bool = True

@dataclass(frozen=True)
class ProfileMatch:
    profile_id: str
    confidence: float
    reasons: tuple[str, ...]
    candidates: tuple[str, ...]

PROFILE_DECLARATIONS = {
    "native-pe": ProfileDeclaration("native-pe", ("PE32", "PE32+"), ("pe:rva", "pe:file"), ("ghidra", "rizin", "angr", "retdec", "binaryninja")),
    "native-elf": ProfileDeclaration("native-elf", ("ELF32", "ELF64"), ("elf:vaddr", "elf:file"), ("ghidra", "rizin", "angr", "retdec", "binaryninja")),
    "dotnet": ProfileDeclaration("dotnet", ("CLR assembly",), ("dotnet:token", "dotnet:il"), ("ilspy",)),
    "android-apk": ProfileDeclaration("android-apk", ("APK", "DEX"), ("dex:method", "dex:offset", "resource:path"), ("jadx", "apktool", "ghidra")),
    "wasm": ProfileDeclaration("wasm", ("WebAssembly",), ("wasm:function", "wasm:offset"), ("wabt", "binaryen")),
    "macho": ProfileDeclaration("macho", ("Mach-O32", "Mach-O64", "Mach-O fat"), ("macho:vmaddr", "macho:file"), ("rizin", "ghidra")),
    "jvm": ProfileDeclaration("jvm", ("class", "JAR"), ("jvm:class", "jvm:method", "jvm:bci"), ("cfr",)),
    "firmware": ProfileDeclaration("firmware", ("raw", "Intel HEX"), ("firmware:physical", "firmware:file"), ("rizin", "ghidra")),
}
```

Inspect ZIP central-directory names without extracting; cap entries at 10,000 and total declared bytes at 512 MiB. Identify CLR only after PE structure shows a valid COM descriptor; a bare `MZ` is `native-pe`. Raw firmware always needs explicit `--profile firmware` because arbitrary bytes cannot be certified from magic alone.

- [ ] **Step 4: Run classifier, triage, and adversarial regressions**

Run: `python -m pytest tests/test_static_profiles.py tests/test_adversarial_boundaries.py tests/test_project.py -q`

Expected: all tests pass and existing magic labels remain compatible.

- [ ] **Step 5: Commit profile routing**

```bash
git add aether_re/static_profiles.py aether_re/engines/triage.py tests/test_static_profiles.py
git commit -m "feat(profiles): route static analysis by verified content"
```

#### Task 2B: Pinned static worker contract and license boundary

**Files:**
- Create: `aether_re/static_worker.py`
- Create: `tools/static_workers.lock.json`
- Modify: `aether_re/contracts.py`
- Test: `tests/test_static_worker.py`
- Test: `tests/test_contracts.py`

**Interfaces:**
- Consumes: `StaticWorkerSpec`, an argument tuple, input snapshot, and dedicated output directory.
- Produces: `probe_static_worker(spec: StaticWorkerSpec) -> StaticWorkerProbe` and `run_static_worker(spec: StaticWorkerSpec, args: tuple[str, ...], input_path: Path, out_dir: Path) -> dict[str, Any]`.

- [ ] **Step 1: Write failing probe, hash-race, shell, and output-bound tests**

```python
import hashlib
from pathlib import Path
import pytest
from aether_re.static_worker import StaticWorkerSpec, run_static_worker


def spec(exe: Path) -> StaticWorkerSpec:
    return StaticWorkerSpec("fake", exe, hashlib.sha256(exe.read_bytes()).hexdigest(),
                            "Fake 1.0", "MIT", 5.0, 128, 10, 1_000_000)


def test_worker_rejects_executable_changed_after_probe(tmp_path):
    exe = tmp_path / "fake.exe"
    exe.write_bytes(b"first")
    pinned = spec(exe)
    exe.write_bytes(b"second")
    with pytest.raises(ValueError, match="worker_executable_hash_mismatch"):
        run_static_worker(pinned, ("--json",), tmp_path / "input", tmp_path / "out")


def test_worker_rejects_shell_metacharacters_and_unbounded_output(tmp_path):
    exe = tmp_path / "fake.exe"; exe.write_bytes(b"binary")
    with pytest.raises(ValueError, match="worker_argument_forbidden"):
        run_static_worker(spec(exe), ("&&", "calc.exe"), tmp_path / "input", tmp_path / "out")
```

Use a monkeypatched `run_bounded` test to return oversized stdout and assert terminal state `failed` with `error == "worker_output_limit_exceeded"`.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `python -m pytest tests/test_static_worker.py tests/test_contracts.py -q`

Expected: import failure for `aether_re.static_worker`.

- [ ] **Step 3: Implement the exact worker types and validation**

```python
@dataclass(frozen=True)
class StaticWorkerSpec:
    name: str
    executable: Path
    executable_sha256: str
    expected_version: str
    license_spdx: str
    timeout_s: float
    memory_mb: int
    cpu_s: int
    max_output_bytes: int

@dataclass(frozen=True)
class StaticWorkerProbe:
    name: str
    available: bool
    executable_sha256: str
    version: str
    license_spdx: str
    errors: tuple[str, ...]
```

`run_static_worker` resolves both input and output, requires a regular non-symlink input, requires a new output directory outside the input parent, re-hashes the executable immediately before `run_bounded`, passes `cwd=out_dir`, and sets no target-derived environment variables. Reject `|`, `&`, `;`, redirections, newline, NUL, response-file arguments, and paths outside the worker directory/output/input snapshot. Add `validate_static_worker_result(name: str, result: dict[str, Any]) -> dict[str, Any]` with schema `static-worker-result.v1` and the same terminal states as `adapter-result.v1`.

The lock file starts as a schema-valid empty registry:

```json
{"schema":"static-workers-lock.v1","workers":[],"policy":{"network":"denied","target_execution":false,"shell":false}}
```

Real entries are added only by the operator-facing probe command in Task 12 after executable hash, version, and SPDX license are observed. Empty registry means all optional workers are unavailable, not successful.

- [ ] **Step 4: Run worker, process, cleanup, and contract regressions**

Run: `python -m pytest tests/test_static_worker.py tests/test_process.py tests/test_process_cleanup.py tests/test_contracts.py -q`

Expected: all pass; no worker fixture launches a target artifact.

- [ ] **Step 5: Commit the worker boundary**

```bash
git add aether_re/static_worker.py aether_re/contracts.py tools/static_workers.lock.json tests/test_static_worker.py tests/test_contracts.py
git commit -m "feat(workers): enforce pinned bounded static analyzers"
```

### Task 3: Normalize native PE/ELF evidence before consensus

**Files:**
- Create: `aether_re/engines/native_normalize.py`
- Modify: `aether_re/engines/pe_elf.py:12-659`
- Modify: `aether_re/pipeline.py:249-359,398-474`
- Test: `tests/test_native_normalize.py`
- Test: `tests/test_pe_structure.py`
- Test: `tests/test_elf_structure.py`

**Interfaces:**
- Consumes: `normalize_native_structure(artifact_id: str, profile_id: str, structure: dict[str, Any], evidence_ref: str) -> IRDocument` and `normalize_function_evidence(document: IRDocument, items: list[FunctionEvidence]) -> IRDocument`.
- Produces: one canonical native document containing sections, segments, imports, exports, symbols, relocations, functions, and calls in explicit PE or ELF address spaces.

- [ ] **Step 1: Write failing address-space, truncation, and mixed-source tests**

```python
from aether_re.engines.native_normalize import normalize_native_structure
from aether_re.kernel_contracts import EpistemicState


def test_pe_rva_and_file_offset_do_not_alias():
    structure = {"format": "PE32+", "parse_status": "complete", "sections": [
        {"name": ".text", "va": "0x400", "raw_offset": "0x400", "raw_size": 16}
    ], "segments": [], "imports": [], "exports": [], "symbols": [], "relocations": []}
    doc = normalize_native_structure("sha256:x", "native-pe", structure, "ev:structure")
    locations = {(n.location.space, n.location.value) for n in doc.nodes}
    assert ("pe:rva", "0x400") in locations and ("pe:file", "0x400") in locations


def test_partial_elf_declares_losses_instead_of_guessing():
    doc = normalize_native_structure("sha256:y", "native-elf", {"format": "ELF64", "parse_status": "partial",
        "parse_errors": ["section_table_truncated"], "sections": [], "segments": [], "imports": [],
        "exports": [], "symbols": [], "relocations": []}, "ev:structure")
    assert "section_table" in doc.losses
    assert all(n.epistemic_state is not EpistemicState.EXACT for n in doc.nodes)
```

Add a test proving Ghidra VA `0x140001000` and Rizin RVA `0x1000` merge only when PE image base `0x140000000` is an `EXACT` structure node.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -m pytest tests/test_native_normalize.py -q`

Expected: import failure for `native_normalize`.

- [ ] **Step 3: Expose parse completeness and implement normalization**

```python
def normalize_native_structure(artifact_id: str, profile_id: str,
                               structure: dict[str, Any], evidence_ref: str) -> IRDocument:
    if profile_id not in {"native-pe", "native-elf"}:
        raise ValueError("native_profile_required")
    status = structure.get("parse_status", "partial")
    state = "EXACT" if status == "complete" else "UNKNOWN"
    losses = tuple(sorted({
        loss for loss, missing in (
            ("section_table", "section_table_truncated" in structure.get("parse_errors", [])),
            ("symbol_table", "symbol_table_unavailable" in structure.get("parse_errors", [])),
            ("relocations", "relocations_unavailable" in structure.get("parse_errors", [])),
        ) if missing
    }))
    # create distinct nodes for file and virtual locations; connect them with
    # mapped_to only when sizes and image mapping are directly observed
```

Return `parse_status` (`complete`, `partial`, `invalid`) and `parse_errors` from both PE and ELF parsers. In `pipeline.run_megazord`, call `select_static_profile` after the verified snapshot, normalize the structure, add normalized adapter functions, validate the combined document, project it, and populate `report.profile` and `report.ir`. Keep legacy report lists populated from the same source during migration.

- [ ] **Step 4: Run native, identity, pipeline, and graph regressions**

Run: `python -m pytest tests/test_native_normalize.py tests/test_pe_structure.py tests/test_elf_structure.py tests/test_identity.py tests/test_pipeline_guards.py tests/test_project.py -q`

Expected: all pass and no native target is executed.

- [ ] **Step 5: Commit native normalization**

```bash
git add aether_re/engines/native_normalize.py aether_re/engines/pe_elf.py aether_re/pipeline.py tests/test_native_normalize.py tests/test_pe_structure.py tests/test_elf_structure.py
git commit -m "feat(native): normalize PE and ELF evidence into canonical IR"
```

### Task 4: Conflict-preserving consensus and cited reconstruction

**Files:**
- Modify: `aether_re/models.py:27-71`
- Modify: `aether_re/engines/consensus.py:12-206`
- Test: `tests/test_consensus_calibrated.py`
- Test: `tests/test_ensemble.py`

**Interfaces:**
- Consumes: `FunctionEvidence` with explicit `address_space`, `evidence_refs`, `epistemic_state`, and backend reliability supplied by a profile certificate.
- Produces: `merge_function_evidence(items, successful_sources=None, base_addr=0, reliability=None) -> list[FunctionConsensus]` retaining conflicts and alternatives.

- [ ] **Step 1: Write failing tests against blind majority and mixed address spaces**

```python
from aether_re.engines.consensus import merge_function_evidence
from aether_re.kernel_contracts import EpistemicState
from aether_re.models import FunctionEvidence


def ev(source, name, confidence, space="elf:vaddr"):
    return FunctionEvidence(address="0x1000", name=name, source=source, confidence=confidence,
        quality=.8, address_space=space, evidence_refs=[f"ev:{source}"], epistemic_state=EpistemicState.PROBABILISTIC_INFERENCE)


def test_calibrated_backend_beats_correlated_majority_and_preserves_conflict():
    merged = merge_function_evidence([ev("ghidra", "safe", .8), ev("rizin", "wrong", .9), ev("retdec", "wrong", .9)],
                                     reliability={"ghidra": .95, "rizin": .55, "retdec": .50})
    assert merged[0].name == "safe"
    assert merged[0].conflicts[0]["field"] == "name"
    assert merged[0].epistemic_state is EpistemicState.PROBABILISTIC_INFERENCE


def test_same_number_in_different_spaces_never_merges():
    assert len(merge_function_evidence([ev("ilspy", "M", .9, "dotnet:il"), ev("ghidra", "M", .9, "pe:rva")])) == 2
```

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -m pytest tests/test_consensus_calibrated.py -q`

Expected: `FunctionEvidence` rejects the new arguments or consensus merges incompatible spaces.

- [ ] **Step 3: Implement calibrated weighting and explicit conflicts**

Add these fields with backward-compatible defaults:

```python
address_space: str = "unknown"
evidence_refs: list[str] = field(default_factory=list)
epistemic_state: EpistemicState = EpistemicState.UNKNOWN
losses: list[str] = field(default_factory=list)
```

Add `conflicts: list[dict[str, Any]]`, `alternatives: list[dict[str, Any]]`, and `epistemic_state: EpistemicState` to `FunctionConsensus`. Group by `(address_space, normalized_address)`. Weight each item by `reliability[source] * confidence * quality`, default uncalibrated reliability to `0.25`, cap single-source evidence at `0.80`, and never promote beyond `PROBABILISTIC_INFERENCE` from agreement alone. Remove the fixed five-backend coverage denominator; use the profile-selected backend set passed by the caller.

- [ ] **Step 4: Run consensus and project regressions**

Run: `python -m pytest tests/test_consensus_calibrated.py tests/test_ensemble.py tests/test_project.py tests/test_native_normalize.py -q`

Expected: all pass; legacy fixtures without calibration are explicitly low-confidence rather than rejected.

- [ ] **Step 5: Commit calibrated consensus**

```bash
git add aether_re/models.py aether_re/engines/consensus.py tests/test_consensus_calibrated.py tests/test_ensemble.py
git commit -m "feat(consensus): preserve conflicts and calibrated reliability"
```

#### Task 4B: Reconstruction units with epistemic labels and citations

**Files:**
- Modify: `aether_re/engines/reconstruct.py:69-302`
- Modify: `aether_re/pipeline.py:344-359,477-520`
- Test: `tests/test_reconstruction_provenance.py`

**Interfaces:**
- Consumes: canonical `IRDocument` and merged `FunctionConsensus` records.
- Produces: `ReconstructionUnit`, `build_reconstruction(document: IRDocument, functions: list[FunctionConsensus]) -> tuple[ReconstructionUnit, ...]`, and `render_reconstruction(units: tuple[ReconstructionUnit, ...], language: str) -> str`.

- [ ] **Step 1: Write failing citation, abstention, and label tests**

```python
from aether_re.engines.reconstruct import build_reconstruction, render_reconstruction
from aether_re.kernel_contracts import EpistemicState


def test_every_rendered_function_has_state_evidence_and_losses(ir_document, consensus_function):
    units = build_reconstruction(ir_document, [consensus_function])
    assert units[0].epistemic_state in set(EpistemicState)
    assert units[0].evidence_refs
    text = render_reconstruction(units, "c-like")
    assert "evidence:" in text and "state:" in text and "losses:" in text


def test_unknown_body_abstains_instead_of_inventing_calls(ir_document):
    unit = build_reconstruction(ir_document, [])[0]
    assert unit.epistemic_state is EpistemicState.UNKNOWN
    assert "body unavailable" in unit.body
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `python -m pytest tests/test_reconstruction_provenance.py -q`

Expected: imports fail because the reconstruction interfaces do not exist.

- [ ] **Step 3: Implement cited reconstruction without original-source claims**

```python
@dataclass(frozen=True)
class ReconstructionUnit:
    identity: str
    name: str
    address_space: str
    address: str
    body: str
    epistemic_state: EpistemicState
    confidence: float
    evidence_refs: tuple[str, ...]
    losses: tuple[str, ...]
    alternatives: tuple[dict[str, Any], ...]
```

Render a provenance comment before every unit. Use backend pseudocode only when its evidence reference exists in the IR. Render conflicting names/bodies as alternatives in the JSON report, not as merged executable syntax. Rename the published artifact to `reconstruction.c` while writing `pseudo_source.c` as a compatibility copy containing the same warning header.

- [ ] **Step 4: Run reconstruction and pipeline regressions**

Run: `python -m pytest tests/test_reconstruction_provenance.py tests/test_ensemble.py tests/test_project.py tests/test_evidence.py -q`

Expected: all pass; no rendered unit lacks evidence/state/loss metadata.

- [ ] **Step 5: Commit evidence-backed reconstruction**

```bash
git add aether_re/engines/reconstruct.py aether_re/pipeline.py tests/test_reconstruction_provenance.py
git commit -m "feat(reconstruct): cite every reconstructed unit"
```

### Task 5: Certifiable .NET managed profile

Implement the .NET vertical slice and run its complete gate; Task 7 later adds JVM using the same worker/IR contracts without sharing address spaces or identity rules.

**Files:**
- Create: `aether_re/adapters/ilspy.py`
- Modify: `aether_re/adapters/__init__.py`
- Modify: `aether_re/pipeline.py`
- Create: `tests/test_adapter_ilspy.py`
- Create: `tests/fixtures/static_profiles/dotnet/oracle.json`
- Create: `tests/fixtures/static_profiles/dotnet/LICENSE.txt`
- Create: `tests/fixtures/static_profiles/dotnet/SHA256SUMS`

**Interfaces:**
- Consumes: pinned `ilspycmd` worker output and profile `dotnet` from Task 3.
- Produces: `ILSpyAdapter.probe()`, `ILSpyAdapter.analyze(target: Path, out_dir: Path) -> dict[str, Any]`, and `normalize_ilspy(payload: dict[str, Any], artifact_id: str, evidence_ref: str) -> IRDocument`.

- [ ] **Step 1: Write failing CLR normalization and malformed-output tests**

```python
import pytest
from aether_re.adapters.ilspy import normalize_ilspy


def test_ilspy_preserves_tokens_il_offsets_types_and_calls(dotnet_payload):
    doc = normalize_ilspy(dotnet_payload, "sha256:dotnet", "ev:ilspy")
    assert any(n.location.space == "dotnet:token" and n.kind == "method" for n in doc.nodes)
    assert any(n.kind == "type" for n in doc.nodes)
    assert any(e.kind == "calls" for e in doc.edges)


def test_ilspy_unknown_schema_fails_closed():
    with pytest.raises(ValueError, match="ilspy_schema_unsupported"):
        normalize_ilspy({"schema": "future"}, "sha256:x", "ev:x")
```

Add ReadyToRun input coverage: it must declare `native_code_mapping` loss unless an independent native mapping is present. Add absent-PDB coverage: local names are `UNKNOWN`, not inferred as exact.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -m pytest tests/test_adapter_ilspy.py -q`

Expected: import failure for `aether_re.adapters.ilspy`.

- [ ] **Step 3: Implement ILSpy as an external MIT-licensed worker**

Use `StaticWorkerSpec` and `run_static_worker`; do not import or copy `ICSharpCode.Decompiler`. Normalize assembly/module/type/method/field/resource nodes, `contains`, `calls`, `inherits`, and `implements` edges. Use metadata tokens and IL offsets, preserve generated C# only as `VERIFIED_RECONSTRUCTION` after oracle comparison, otherwise `PROBABILISTIC_INFERENCE`. Register the adapter only for `dotnet`.

- [ ] **Step 4: Run .NET, worker, and pipeline tests**

Run: `python -m pytest tests/test_adapter_ilspy.py tests/test_static_worker.py tests/test_static_profiles.py tests/test_pipeline_guards.py -q`

Expected: all pass with ILSpy unavailable on machines lacking a lock entry.

- [ ] **Step 5: Commit the .NET profile**

```bash
git add aether_re/adapters/ilspy.py aether_re/adapters/__init__.py aether_re/pipeline.py tests/test_adapter_ilspy.py tests/fixtures/static_profiles/dotnet
git commit -m "feat(dotnet): add provenance-safe ILSpy profile"
```

### Task 6: Certifiable Android and WebAssembly profiles

Android and WebAssembly own disjoint adapter files and fixtures and may be delegated in parallel after Tasks 1–4 merge.

**Files:**
- Create: `aether_re/adapters/android.py`
- Modify: `aether_re/adapters/__init__.py`
- Modify: `aether_re/pipeline.py`
- Create: `tests/test_adapter_android.py`
- Create: `tests/fixtures/static_profiles/android/oracle.json`
- Create: `tests/fixtures/static_profiles/android/LICENSE.txt`
- Create: `tests/fixtures/static_profiles/android/SHA256SUMS`

**Interfaces:**
- Consumes: separately pinned JADX and Apktool worker outputs plus native-library child artifact hashes.
- Produces: `AndroidAdapter.analyze(...)` and `normalize_android(jadx: dict[str, Any], apktool: dict[str, Any], artifact_id: str, evidence_refs: tuple[str, str]) -> IRDocument`.

- [ ] **Step 1: Write failing manifest/resource/DEX/native correlation tests**

```python
from aether_re.adapters.android import normalize_android


def test_android_correlates_manifest_component_dex_method_and_native_library(jadx_payload, apktool_payload):
    doc = normalize_android(jadx_payload, apktool_payload, "sha256:apk", ("ev:jadx", "ev:apktool"))
    kinds = {n.kind for n in doc.nodes}
    assert {"android_component", "dex_method", "resource", "native_child_artifact"} <= kinds
    assert any(e.kind == "loads_native_library" for e in doc.edges)


def test_android_keeps_conflicting_resource_names(android_conflict_payloads):
    doc = normalize_android(*android_conflict_payloads, "sha256:apk", ("ev:j", "ev:a"))
    assert "resource_name_conflict" in doc.losses
```

Add archive traversal, duplicate entry, 10,001-entry, and 512 MiB declared-size tests. No fixture is extracted outside the case workspace.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -m pytest tests/test_adapter_android.py -q`

Expected: import failure for `aether_re.adapters.android`.

- [ ] **Step 3: Implement two-worker correlation**

Keep JADX and Apktool as separate Apache-2.0 external workers. Model manifest components, permissions, intent filters, resources, classes, methods, fields, DEX calls, and native library child artifacts. A claim corroborated by both workers receives two evidence refs but is not automatically `EXACT`; decoded resources are `VERIFIED_RECONSTRUCTION` only when round-trip tests match. Native `.so` entries are hashed and submitted to the native-ELF normalizer without execution.

- [ ] **Step 4: Run Android, archive-boundary, and pipeline tests**

Run: `python -m pytest tests/test_adapter_android.py tests/test_adversarial_boundaries.py tests/test_static_profiles.py tests/test_pipeline_guards.py -q`

Expected: all pass; every extracted child remains beneath the dedicated output directory.

- [ ] **Step 5: Commit the Android profile**

```bash
git add aether_re/adapters/android.py aether_re/adapters/__init__.py aether_re/pipeline.py tests/test_adapter_android.py tests/fixtures/static_profiles/android
git commit -m "feat(android): correlate JADX Apktool and native evidence"
```

#### Task 6B: WebAssembly with WABT/Binaryen round trip

**Files:**
- Create: `aether_re/adapters/wasm.py`
- Modify: `aether_re/adapters/__init__.py`
- Modify: `aether_re/pipeline.py`
- Create: `tests/test_adapter_wasm.py`
- Create: `tests/fixtures/static_profiles/wasm/minimal.wasm`
- Create: `tests/fixtures/static_profiles/wasm/oracle.json`
- Create: `tests/fixtures/static_profiles/wasm/LICENSE.txt`
- Create: `tests/fixtures/static_profiles/wasm/SHA256SUMS`

**Interfaces:**
- Consumes: pinned `wasm-objdump` JSON/text, `wasm2wat`, and Binaryen validation output.
- Produces: `WasmAdapter.analyze(...)` and `normalize_wasm(payload: dict[str, Any], artifact_id: str, evidence_ref: str) -> IRDocument`.

- [ ] **Step 1: Write failing section/index/indirect-call/round-trip tests**

```python
from aether_re.adapters.wasm import normalize_wasm


def test_wasm_preserves_indices_imports_exports_and_indirect_calls(wasm_payload):
    doc = normalize_wasm(wasm_payload, "sha256:wasm", "ev:wabt")
    assert any(n.location.space == "wasm:function" for n in doc.nodes)
    assert any(e.kind == "calls_indirect" and "table_index" in e.attributes for e in doc.edges)
    assert any(n.kind == "custom_section" for n in doc.nodes)


def test_wasm_name_section_absence_is_declared_loss(wasm_without_names):
    assert "function_names" in normalize_wasm(wasm_without_names, "sha256:w", "ev:w").losses
```

Add a canonical round-trip fixture: original module and WAT→WASM rebuild must have equivalent validated module structure while byte inequality is reported rather than treated as failure.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -m pytest tests/test_adapter_wasm.py -q`

Expected: import failure for `aether_re.adapters.wasm`.

- [ ] **Step 3: Implement Apache-2.0 WABT/Binaryen workers and normalization**

Normalize types, imports, functions, tables, memories, globals, exports, elements, data, custom sections, direct calls, and indirect calls. Preserve function index separately from byte offset. WAT is `VERIFIED_RECONSTRUCTION` only after validator and structural round trip; it is never called original source. WABT and Binaryen remain distinct workers so correlated parser bugs do not count as independent proof automatically.

Create the minimal module deterministically with `python -c "from pathlib import Path; Path('tests/fixtures/static_profiles/wasm/minimal.wasm').write_bytes(bytes.fromhex('0061736d01000000'))"`, record its SHA-256 in `SHA256SUMS`, and state in `oracle.json` that it contains the version-1 header and no sections/functions.

- [ ] **Step 4: Run WASM, worker, and pipeline tests**

Run: `python -m pytest tests/test_adapter_wasm.py tests/test_static_worker.py tests/test_static_profiles.py tests/test_pipeline_guards.py -q`

Expected: all pass and malformed sections fail before graph publication.

- [ ] **Step 5: Commit the WebAssembly profile**

```bash
git add aether_re/adapters/wasm.py aether_re/adapters/__init__.py aether_re/pipeline.py tests/test_adapter_wasm.py tests/fixtures/static_profiles/wasm
git commit -m "feat(wasm): add validated WABT Binaryen profile"
```

### Task 7: Mach-O, JVM, firmware, certification, and release gate

**Files:**
- Create: `aether_re/adapters/macho.py`
- Create: `aether_re/adapters/jvm.py`
- Create: `aether_re/adapters/firmware.py`
- Modify: `aether_re/adapters/__init__.py`
- Modify: `aether_re/pipeline.py`
- Create: `tests/test_adapter_macho.py`
- Create: `tests/test_adapter_jvm.py`
- Create: `tests/test_adapter_firmware.py`
- Create: `tests/fixtures/static_profiles/macho/oracle.json`
- Create: `tests/fixtures/static_profiles/jvm/oracle.json`
- Create: `tests/fixtures/static_profiles/firmware/oracle.json`

**Interfaces:**
- Consumes: Rizin/Ghidra observations for Mach-O, a pinned Apache-compatible or MIT JVM decompiler worker, and explicit firmware layout declarations.
- Produces: `normalize_macho`, `normalize_jvm`, and `normalize_firmware`, each returning `IRDocument`.

- [ ] **Step 1: Write failing tests for each expansion boundary**

```python
def test_macho_fat_keeps_slice_architecture_and_vmaddr_distinct(macho_fat_payload):
    doc = normalize_macho(macho_fat_payload, "sha256:m", "ev:m")
    assert {n.attributes.get("architecture") for n in doc.nodes if n.kind == "slice"} == {"x86_64", "arm64"}


def test_jvm_overloaded_methods_have_descriptor_qualified_identity(jvm_payload):
    doc = normalize_jvm(jvm_payload, "sha256:j", "ev:j")
    methods = [n for n in doc.nodes if n.kind == "jvm_method" and n.name == "parse"]
    assert len({n.attributes["descriptor"] for n in methods}) == 2
    assert len({n.identity for n in methods}) == 2


def test_raw_firmware_requires_explicit_layout_and_never_guesses_base(raw_payload):
    with pytest.raises(ValueError, match="firmware_layout_required"):
        normalize_firmware(raw_payload, "sha256:f", "ev:f", layout=None)
```

Also test Intel HEX checksum failure, Mach-O code-signature preservation, JVM unknown class-file major version, firmware overlapping regions, and unknown backend schema preservation with certifying status refused.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -m pytest tests/test_adapter_macho.py tests/test_adapter_jvm.py tests/test_adapter_firmware.py -q`

Expected: import failures for the three new adapters.

- [ ] **Step 3: Implement distinct address models and conservative claims**

Mach-O: model fat slices, load commands, segments, sections, symbols, imports, exports, relocations, Objective-C metadata, code-signature blob, and per-slice VM address spaces. JVM: model class/module/package, constant pool, descriptors, methods, fields, annotations, inheritance, interfaces, bytecode offsets, and calls. Firmware: accept only an explicit JSON layout containing architecture, endianness, base address, region offsets/sizes/hashes, or validated Intel HEX addressing; unknown raw layout remains `UNKNOWN`.

Rizin is LGPL-3.0 and Ghidra is Apache-2.0, both out of process. The selected JVM worker's SPDX identifier must be in `static_workers.lock.json`; no JVM backend is selected until its license record is present. Firmware container extraction remains outside this task; only already-authorized layout regions are normalized.

- [ ] **Step 4: Run expansion and native regressions**

Run: `python -m pytest tests/test_adapter_macho.py tests/test_adapter_jvm.py tests/test_adapter_firmware.py tests/test_native_normalize.py tests/test_static_profiles.py -q`

Expected: all pass, with unsupported versions and missing layouts abstaining explicitly.

- [ ] **Step 5: Commit expansion profiles**

```bash
git add aether_re/adapters/macho.py aether_re/adapters/jvm.py aether_re/adapters/firmware.py aether_re/adapters/__init__.py aether_re/pipeline.py tests/test_adapter_macho.py tests/test_adapter_jvm.py tests/test_adapter_firmware.py tests/fixtures/static_profiles/macho tests/fixtures/static_profiles/jvm tests/fixtures/static_profiles/firmware
git commit -m "feat(profiles): add bounded Mach-O JVM and firmware normalization"
```

#### Task 7B: Profile certification, CLI integration, license matrix, and final regression

**Files:**
- Create: `aether_re/profile_certification.py`
- Create: `docs/static-profile-matrix.md`
- Modify: `megazord.py:119-167` and parser construction near existing `analyze`/gate commands
- Modify: `README.md`
- Test: `tests/test_profile_certification.py`
- Test: `tests/test_static_profile_cli.py`

**Interfaces:**
- Consumes: profile scope, sealed corpus manifest, worker lock, evaluation reports, baseline report, candidate report, and limitations.
- Produces: `certify_static_profile(profile_scope: dict[str, Any], corpus: dict[str, Any], workers: dict[str, Any], evaluation: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]`, CLI `profile-probe`, CLI `profile-certify`, and `analyze --profile`.

- [ ] **Step 1: Write failing certification and CLI tests**

```python
from aether_re.profile_certification import certify_static_profile


def test_profile_cannot_certify_without_relations_or_independent_oracle(valid_scope, sealed_corpus, locked_workers):
    result = certify_static_profile(valid_scope, sealed_corpus, locked_workers,
        {"entities": {"precision": 1.0, "recall": 1.0}, "relations": {"status": "unmeasured"}, "oracle_independent": False},
        {"regressions": []})
    assert result["status"] == "NAO_COMPROVADA"
    assert {e["code"] for e in result["errors"]} >= {"relations_unmeasured", "independent_oracle_missing"}


def test_profile_rejects_worker_hash_or_license_gap(valid_inputs):
    valid_inputs["workers"]["workers"][0]["executable_sha256"] = "0" * 64
    result = certify_static_profile(**valid_inputs)
    assert result["status"] != "QUITADA"
    assert any(e["code"] == "worker_pin_invalid" for e in result["errors"])
```

CLI tests must assert: ambiguous auto-detection exits 2; requested/profile mismatch exits 2; missing optional worker is reported as unavailable and exits 2 for certification; successful probe writes deterministic JSON; `analyze --profile firmware` without layout exits 2; no traceback or target execution occurs.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -m pytest tests/test_profile_certification.py tests/test_static_profile_cli.py -q`

Expected: imports or parser commands are absent.

- [ ] **Step 3: Implement the certification denominator and commands**

```python
REQUIRED_MEASUREMENTS = ("entities", "relations", "abstention", "calibration", "reproducibility")

def sha256_canonical(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def certify_static_profile(profile_scope, corpus, workers, evaluation, baseline):
    errors = []
    # validate profile-scope.v1, distinct development/calibration/blind hashes,
    # authorization, independent oracle, denominators, confidence intervals,
    # worker hashes/licenses, declared losses, and zero critical regression
    status = "QUITADA" if not errors else "NAO_COMPROVADA"
    return {"schema": "static-profile-certificate.v1", "profile_id": profile_scope["profile_id"],
            "status": status, "errors": errors, "measurements": evaluation,
            "worker_lock_sha256": sha256_canonical(workers), "limitations": sorted(evaluation.get("limitations", []))}
```

`profile-probe --registry tools/static_workers.lock.json --out output/worker-probe.json` reads configured executable paths, runs only version commands, records observed hash/version/license, and never modifies the registry automatically. A human-reviewed exact lock update is a separate commit. `profile-certify` takes explicit `--scope`, `--corpus`, `--workers`, `--evaluation`, `--baseline`, and `--out` paths. `analyze --profile` passes the requested profile to `run_megazord(..., profile_id=args.profile)`.

Document matrix rows for `native-pe`, `native-elf`, `dotnet`, `android-apk`, `wasm`, `macho`, `jvm`, and `firmware`; each row names exact formats/architectures exercised, worker SPDX licenses, measured entities/relations, corpus count, status, and exclusions. Unmeasured cells say `NAO_COMPROVADA`, never a check mark.

- [ ] **Step 4: Run the complete static-profile gate and full suite**

Run:

```powershell
python -m pytest tests/test_ir.py tests/test_ir_graph.py tests/test_static_profiles.py tests/test_static_worker.py tests/test_native_normalize.py tests/test_consensus_calibrated.py tests/test_reconstruction_provenance.py tests/test_adapter_ilspy.py tests/test_adapter_android.py tests/test_adapter_wasm.py tests/test_adapter_macho.py tests/test_adapter_jvm.py tests/test_adapter_firmware.py tests/test_profile_certification.py tests/test_static_profile_cli.py -q
python -m pytest -q
python megazord.py profile-probe --registry tools/static_workers.lock.json --out output/static_worker_probe.json
```

Expected: focused tests and full suite pass; probe returns deterministic results without analyzing or executing a target. For each profile with a sealed blind corpus and installed locked workers, run `profile-certify` and require exit 0 only when status is `QUITADA`; every other profile remains explicitly `NAO_COMPROVADA`.

- [ ] **Step 5: Verify reproducible report artifacts and hashes**

Run:

```powershell
python megazord.py analyze tests/fixtures/static_profiles/wasm/minimal.wasm --profile wasm --out output/profile_wasm_replay
python megazord.py graph-ingest --input output/profile_wasm_replay/ir_graph.json --db output/profile_wasm_replay/graph.sqlite --run-id wasm-replay-001 --out output/profile_wasm_replay/graph_ingest.json
python megazord.py graph-verify --db output/profile_wasm_replay/graph.sqlite --out output/profile_wasm_replay/graph_verify.json
Get-FileHash output/profile_wasm_replay/report.json,output/profile_wasm_replay/ir.json,output/profile_wasm_replay/ir_graph.json -Algorithm SHA256
```

Expected: manifest identity matches the fixture, graph verification is valid, every reconstruction unit cites evidence, and repeated clean runs produce equal canonical IR/graph content hashes after excluding run timestamps.

- [ ] **Step 6: Commit certification and operator documentation**

```bash
git add aether_re/profile_certification.py megazord.py README.md docs/static-profile-matrix.md tests/test_profile_certification.py tests/test_static_profile_cli.py
git commit -m "feat(certification): gate every static profile independently"
```

## Execution Order and Review Gates

1. Tasks 1–2 establish shared contracts and must merge before adapter work.
2. Tasks 3–4 complete the native vertical slice and establish the no-regression baseline.
3. Tasks 5 and 6 may run in parallel after Task 4 because they own separate adapters and fixtures.
4. Task 7 begins after Task 4; its Mach-O and firmware adapter subcycle may run alongside Tasks 5–6, but its certification subcycle runs only after all profile branches are integrated.
6. Every adapter task receives a contract review and a fixture/license review by an agent other than its implementer.
7. A full-suite regression is mandatory after each parallel integration batch; a failed legacy test blocks the batch.

## Completion Evidence

This plan is complete only when the implementation produces all of the following without extrapolation:

- Canonical `ir.v1` and `forensic-graph.v2` artifacts with deterministic hashes.
- No node, edge, or reconstruction unit without evidence references and epistemic state.
- Native PE and ELF behavior equal to or better than the frozen baseline on identical corpus identities.
- Separate certificates for each profile; absent corpora, workers, relations, calibration, or independent oracles result in `NAO_COMPROVADA`.
- Worker executable hashes, versions, licenses, time/memory/CPU/output limits, and non-execution policy recorded.
- Full pytest suite green, graph verification green, clean replay hashes recorded, and no critical integrity error.
- Documentation states exact tested formats and architectures and preserves every exclusion.
