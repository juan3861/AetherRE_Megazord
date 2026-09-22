# Evidence Kernel and Universal Intake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the fail-closed Evidence Kernel, hash-chained custody journal, bounded Universal Intake, deterministic profile router, and versioned worker contracts that become the trusted entry point for every RE_Megazord analysis.

**Architecture:** The implementation keeps the current analyzers intact behind a new trust boundary. Intake snapshots authorized bytes into a content-addressed store, writes every derivation to a durable journal, classifies without executing the target, and routes only to declared profiles; the existing `run_megazord` pipeline then consumes the immutable snapshot rather than the original path. Existing `evidence.py`, `custody.py`, `evidence_contract.py`, `profile_scope.py`, `safe_walk.py`, and adapter-result behavior are preserved through compatibility tests instead of being replaced wholesale.

**Tech Stack:** CPython 3.13 standard library, dataclasses, JSON/JSONL, SHA-256, `pathlib`, `zipfile`, `tarfile`, existing `RunLock`, pytest 8.4.2.

**Spec:** `docs/superpowers/specs/2026-09-22-universal-forensic-reconstruction-design.md`

## Global Constraints

- The five epistemic states are exactly `EXACT`, `VERIFIED_RECONSTRUCTION`, `PROBABILISTIC_INFERENCE`, `HYPOTHESIS`, and `UNKNOWN`.
- Prefer `UNKNOWN` to an unsupported conclusion; never call equivalent pseudocode original source.
- Detect content independently of filename extension and never execute target bytes during intake or routing.
- Every stored object is content-addressed by SHA-256 and every derived object names its parent evidence identifiers.
- Journals are append-only, schema-versioned, hash-chained, durable before acknowledgement, and fail closed on corruption, truncation, or unknown schema.
- Intake rejects symlinks/junctions, path traversal, archive bombs, duplicate archive paths, unsupported special files, and every exceeded file/byte/depth/ratio budget.
- External workers remain replaceable and out of process; worker output is hostile input until schema and budget validation pass.
- Dynamic execution remains forbidden until a separately approved real-VM gate; this plan adds no target execution path.
- Existing local custody remains explicitly non-WORM and `external_anchor=False`; this plan must not strengthen that claim without external proof.
- CPython floor is 3.13 on Windows amd64; production dependencies remain standard-library-only for this slice.
- Tests run with `python -m pytest`; no task may weaken, skip, or delete an existing test.
- The dirty working tree is user state: stage only files named in the current task and never reset unrelated changes.

## Locked File Structure

- Create `aether_re/kernel_contracts.py`: canonical JSON, authorization, limits, artifact/derivation/journal/profile/worker value objects and strict validation.
- Create `aether_re/evidence_store.py`: create-only content-addressed object publication and verification.
- Create `aether_re/evidence_journal.py`: single-writer append-only JSONL journal, hash-chain verification, interrupted-tail recovery report.
- Create `aether_re/archive_intake.py`: bounded ZIP/TAR inspection and extraction into an isolated staging tree.
- Create `aether_re/intake.py`: file/directory/archive intake orchestration, inventory, case manifest, and store/journal coordination.
- Create `aether_re/profile_router.py`: deterministic content-based profile detection and pipeline selection.
- Modify `aether_re/contracts.py`: retain `AdapterResultContract` v1 and add the worker lifecycle protocol validators.
- Modify `aether_re/evidence_contract.py`: accept strict v2 kernel envelopes while retaining legacy record validation.
- Modify `aether_re/pipeline.py`: consume a kernel-produced immutable snapshot and publish kernel references in the final manifest.
- Modify `megazord.py`: add an explicit `intake` command and authorization/limit parsing; preserve `analyze` behavior.
- Create `tests/test_kernel_contracts.py`, `tests/test_evidence_store.py`, `tests/test_evidence_journal.py`, `tests/test_archive_intake.py`, `tests/test_intake.py`, `tests/test_profile_router.py`, `tests/test_worker_contracts_v2.py`, `tests/test_pipeline_kernel.py`, and `tests/test_intake_cli.py`.
- Create `docs/EVIDENCE_KERNEL.md`: operator contract, threat boundary, layouts, replay procedure, and limitation language.

## Review Focus

- A file is replaced between initial stat and publication: the store must reject `source_changed_during_publication`, delete temporary bytes, and publish no journal success entry (Task 2).
- A valid archive contains traversal, symlink, duplicate normalized name, or an extreme compression ratio: inspection must reject the whole container before any member is committed (Task 4).
- Two append attempts occur concurrently or the process dies after a partial final JSONL write: ordering remains unique and recovery reports/quarantines only the incomplete tail without accepting interior corruption (Task 3).
- A polyglot/ambiguous artifact matches more than one profile: the router records all candidates and returns `manual_review` with epistemic state `UNKNOWN`, never an arbitrary first match (Task 6).
- A worker reports success without evidence, changes its planned command, emits unknown fields/schema, or exceeds output budgets: validation returns a typed failure and the pipeline publishes no promoted claim (Task 7).

---

### Task 1: Versioned Kernel Contracts and Canonical Serialization

**Files:**
- Create: `aether_re/kernel_contracts.py`
- Create: `tests/test_kernel_contracts.py`

**Interfaces:**
- Consumes: Python mappings containing authorization, budgets, and evidence metadata.
- Produces: `canonical_json(value: Mapping[str, Any]) -> bytes`; `sha256_canonical(value: Mapping[str, Any]) -> str`; `AuthorizationPolicy.from_dict(value: Mapping[str, Any]) -> AuthorizationPolicy`; `IntakeLimits.from_dict(value: Mapping[str, Any]) -> IntakeLimits`; `ArtifactRef.from_dict(value: Mapping[str, Any]) -> ArtifactRef`; `DerivationRecord.from_dict(value: Mapping[str, Any]) -> DerivationRecord`; `EpistemicState`; `ContractError`.

- [ ] **Step 1: Write failing tests for deterministic encoding and strict enums**

```python
# tests/test_kernel_contracts.py
import pytest

from aether_re.kernel_contracts import (
    AuthorizationPolicy, ContractError, EpistemicState, IntakeLimits,
    canonical_json, sha256_canonical,
)


def test_canonical_json_is_order_independent_and_rejects_nan():
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert sha256_canonical({"a": 1, "b": 2}) == sha256_canonical({"b": 2, "a": 1})
    with pytest.raises(ContractError, match="canonical_json_invalid"):
        canonical_json({"score": float("nan")})


def test_authorization_and_limits_fail_closed():
    policy = AuthorizationPolicy.from_dict({
        "schema": "authorization-policy.v1", "basis": "owner",
        "principal": "local-user", "scope": ["static-analysis"],
    })
    assert policy.allows("static-analysis")
    with pytest.raises(ContractError, match="authorization_scope_invalid"):
        AuthorizationPolicy.from_dict({"schema": "authorization-policy.v1", "basis": "owner", "principal": "x", "scope": []})
    with pytest.raises(ContractError, match="intake_limit_invalid:max_files"):
        IntakeLimits.from_dict({"max_files": True})
    assert {item.value for item in EpistemicState} == {
        "EXACT", "VERIFIED_RECONSTRUCTION", "PROBABILISTIC_INFERENCE", "HYPOTHESIS", "UNKNOWN",
    }
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `python -m pytest tests/test_kernel_contracts.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'aether_re.kernel_contracts'`.

- [ ] **Step 3: Implement canonical values and strict constructors**

```python
# aether_re/kernel_contracts.py
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    pass


class EpistemicState(str, Enum):
    EXACT = "EXACT"
    VERIFIED_RECONSTRUCTION = "VERIFIED_RECONSTRUCTION"
    PROBABILISTIC_INFERENCE = "PROBABILISTIC_INFERENCE"
    HYPOTHESIS = "HYPOTHESIS"
    UNKNOWN = "UNKNOWN"


def canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError("canonical_json_invalid") from exc


def sha256_canonical(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class AuthorizationPolicy:
    schema: str
    basis: str
    principal: str
    scope: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorizationPolicy":
        if value.get("schema") != "authorization-policy.v1":
            raise ContractError("authorization_schema_invalid")
        basis, principal, scope = value.get("basis"), value.get("principal"), value.get("scope")
        if basis not in {"owner", "license", "written-permission", "public-authorized"}:
            raise ContractError("authorization_basis_invalid")
        if not isinstance(principal, str) or not principal.strip():
            raise ContractError("authorization_principal_invalid")
        if not isinstance(scope, list) or not scope or any(not isinstance(item, str) or not item.strip() for item in scope) or len(scope) != len(set(scope)):
            raise ContractError("authorization_scope_invalid")
        return cls("authorization-policy.v1", basis, principal.strip(), tuple(scope))

    def allows(self, operation: str) -> bool:
        return operation in self.scope


@dataclass(frozen=True)
class IntakeLimits:
    max_files: int = 10_000
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_file_bytes: int = 512 * 1024 * 1024
    max_archive_depth: int = 3
    max_compression_ratio: int = 200
    max_path_length: int = 512

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IntakeLimits":
        defaults = asdict(cls())
        unknown = set(value) - set(defaults)
        if unknown:
            raise ContractError("intake_limits_unknown_field")
        merged = {**defaults, **dict(value)}
        for name, limit in merged.items():
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
                raise ContractError(f"intake_limit_invalid:{name}")
        return cls(**merged)


@dataclass(frozen=True)
class ArtifactRef:
    schema: str
    artifact_id: str
    sha256: str
    size: int
    media_type: str
    object_path: str
    origin: str
    authorization_sha256: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactRef":
        required = {"schema", "artifact_id", "sha256", "size", "media_type", "object_path", "origin", "authorization_sha256"}
        if set(value) != required or value.get("schema") != "artifact-ref.v1":
            raise ContractError("artifact_schema_invalid")
        digest = value.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or value.get("artifact_id") != f"sha256:{digest}":
            raise ContractError("artifact_hash_invalid")
        if isinstance(value.get("size"), bool) or not isinstance(value.get("size"), int) or value["size"] < 0:
            raise ContractError("artifact_size_invalid")
        if not isinstance(value.get("authorization_sha256"), str) or not SHA256_RE.fullmatch(value["authorization_sha256"]):
            raise ContractError("authorization_hash_invalid")
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DerivationRecord:
    schema: str
    derivation_id: str
    product: ArtifactRef
    parents: tuple[str, ...]
    producer: Mapping[str, str]
    method: str
    epistemic_state: EpistemicState
    confidence: float | None
    limitations: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DerivationRecord":
        product = ArtifactRef.from_dict(value.get("product", {}))
        state = EpistemicState(value.get("epistemic_state"))
        confidence = value.get("confidence")
        if state in {EpistemicState.EXACT, EpistemicState.UNKNOWN} and confidence is not None:
            raise ContractError("confidence_forbidden")
        if state is EpistemicState.PROBABILISTIC_INFERENCE and (isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0):
            raise ContractError("confidence_invalid")
        return cls(value["schema"], value["derivation_id"], product, tuple(value["parents"]), dict(value["producer"]), value["method"], state, confidence, tuple(value.get("limitations", [])))
```

Implement each constructor with exact schema checks (`authorization-policy.v1`, `artifact-ref.v1`, `derivation-record.v1`), reject booleans where integers are required, require lowercase 64-character hashes, reject empty/duplicate strings, require confidence in `[0.0, 1.0]` only for `PROBABILISTIC_INFERENCE`, and reject confidence for `EXACT`/`UNKNOWN`.

- [ ] **Step 4: Add artifact and derivation invariants to the same test file**

```python
def test_artifact_and_derivation_reject_bad_hash_and_confidence():
    from aether_re.kernel_contracts import ArtifactRef, DerivationRecord
    artifact = {
        "schema": "artifact-ref.v1", "artifact_id": "sha256:" + "a" * 64,
        "sha256": "a" * 64, "size": 3, "media_type": "application/octet-stream",
        "object_path": "objects/sha256/aa/" + "a" * 64, "origin": "input.bin",
        "authorization_sha256": "b" * 64,
    }
    assert ArtifactRef.from_dict(artifact).size == 3
    record = {
        "schema": "derivation-record.v1", "derivation_id": "derive-1",
        "product": artifact, "parents": [artifact["artifact_id"]],
        "producer": {"name": "intake", "version": "1"}, "method": "snapshot",
        "epistemic_state": "EXACT", "confidence": None, "limitations": [],
    }
    assert DerivationRecord.from_dict(record).epistemic_state is EpistemicState.EXACT
    record["confidence"] = 0.9
    with pytest.raises(ContractError, match="confidence_forbidden"):
        DerivationRecord.from_dict(record)
```

- [ ] **Step 5: Run contract tests and the legacy contract tests**

Run: `python -m pytest tests/test_kernel_contracts.py tests/test_contracts.py tests/test_evidence_contract.py -q`

Expected: PASS with no change to `adapter-result.v1` or legacy evidence behavior.

- [ ] **Step 6: Commit only the contract slice**

```powershell
git add -- aether_re/kernel_contracts.py tests/test_kernel_contracts.py
git commit -m "feat(kernel): define strict evidence contracts"
```

### Task 2: Create-Only Evidence Store and Durable Journal

**Files:**
- Create: `aether_re/evidence_store.py`
- Create: `tests/test_evidence_store.py`
- Modify: `aether_re/evidence.py:31-126`

**Interfaces:**
- Consumes: `AuthorizationPolicy`, a regular source file, media type, origin, and `IntakeLimits.max_file_bytes`.
- Produces: `EvidenceStore(root: Path)`; `EvidenceStore.publish_file(source: Path, *, media_type: str, origin: str, authorization: AuthorizationPolicy, max_bytes: int) -> ArtifactRef`; `EvidenceStore.verify(ref: ArtifactRef) -> None`; `EvidenceStore.resolve(ref: ArtifactRef) -> Path`; `PublicationError`.

- [ ] **Step 1: Write RED tests for publication, deduplication, mutation, and links**

```python
# tests/test_evidence_store.py
from pathlib import Path
import pytest

from aether_re.evidence_store import EvidenceStore, PublicationError
from aether_re.kernel_contracts import AuthorizationPolicy


POLICY = AuthorizationPolicy.from_dict({
    "schema": "authorization-policy.v1", "basis": "owner",
    "principal": "test", "scope": ["static-analysis"],
})


def test_store_publishes_create_only_and_deduplicates(tmp_path: Path):
    source = tmp_path / "sample.bin"; source.write_bytes(b"abc")
    store = EvidenceStore(tmp_path / "case")
    first = store.publish_file(source, media_type="application/octet-stream", origin="sample.bin", authorization=POLICY, max_bytes=16)
    second = store.publish_file(source, media_type="application/octet-stream", origin="sample.bin", authorization=POLICY, max_bytes=16)
    assert first == second
    assert store.resolve(first).read_bytes() == b"abc"
    store.verify(first)


def test_store_rejects_oversize_and_link(tmp_path: Path):
    source = tmp_path / "large.bin"; source.write_bytes(b"abcd")
    with pytest.raises(PublicationError, match="source_size_budget_exceeded"):
        EvidenceStore(tmp_path / "case").publish_file(source, media_type="application/octet-stream", origin="large.bin", authorization=POLICY, max_bytes=3)
```

Add a monkeypatched reader test that changes the source after the temporary copy and asserts `source_changed_during_publication`, absence of a final object, and absence of `.tmp` files.

- [ ] **Step 2: Confirm RED**

Run: `python -m pytest tests/test_evidence_store.py -q`

Expected: FAIL during import of `aether_re.evidence_store`.

- [ ] **Step 3: Implement atomic content-addressed publication**

```python
# aether_re/evidence_store.py
class EvidenceStore:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.objects = self.root / "objects" / "sha256"

    def publish_file(self, source: Path, *, media_type: str, origin: str,
                     authorization: AuthorizationPolicy, max_bytes: int) -> ArtifactRef:
        if not authorization.allows("static-analysis"):
            raise PublicationError("operation_not_authorized")
        source = Path(source)
        if _path_has_link(source) or not source.is_file():
            raise PublicationError("source_must_be_regular_file")
        before = sha256_file_bounded(source, max_bytes)
        temporary, copied, observed = self._copy_fsync_bounded(source, max_bytes)
        try:
            if observed != before or sha256_file_bounded(source, max_bytes) != before:
                raise PublicationError("source_changed_during_publication")
            final = self.objects / before[:2] / before
            final.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(temporary, final)
            except FileExistsError:
                if final.stat().st_size != copied or sha256_file(final) != before:
                    raise PublicationError("object_collision_or_corruption") from None
            return ArtifactRef("artifact-ref.v1", f"sha256:{before}", before, copied, media_type, final.relative_to(self.root).as_posix(), origin, sha256_canonical(asdict(authorization)))
        finally:
            temporary.unlink(missing_ok=True)

    def resolve(self, ref: ArtifactRef) -> Path:
        expected = self.root / ref.object_path
        resolved = expected.resolve()
        if self.root not in resolved.parents or resolved.is_symlink():
            raise PublicationError("object_path_escape")
        return resolved

    def verify(self, ref: ArtifactRef) -> None:
        path = self.resolve(ref)
        if path.stat().st_size != ref.size or sha256_file(path) != ref.sha256:
            raise PublicationError("object_integrity_mismatch")
```

Use `os.link(temporary, final)` for create-only publication, accept `FileExistsError` only after size/hash verification, `os.fsync()` before publication, and remove the temporary file in `finally`. Do not use `Path.replace()` on a pre-existing object.

- [ ] **Step 4: Reuse the bounded hash primitive without breaking its API**

In `aether_re/evidence.py`, expose the current private bounded reader as:

```python
def sha256_file_bounded(path: Path, max_bytes: int) -> str:
    return _sha256_bounded(path, max_bytes)
```

Import that function from `evidence_store.py`; keep `create_verified_snapshot(...)` unchanged for compatibility.

- [ ] **Step 5: Run focused and legacy evidence tests**

Run: `python -m pytest tests/test_evidence_store.py tests/test_evidence.py tests/test_cache.py tests/test_custody.py -q`

Expected: PASS; existing snapshot and manifest semantics remain green.

- [ ] **Step 6: Commit the store slice**

```powershell
git add -- aether_re/evidence_store.py aether_re/evidence.py tests/test_evidence_store.py
git commit -m "feat(kernel): add content addressed evidence store"
```

#### Task 2B: Durable Hash-Chained Evidence Journal and Recovery

**Files:**
- Create: `aether_re/evidence_journal.py`
- Create: `tests/test_evidence_journal.py`

**Interfaces:**
- Consumes: a case directory plus bounded event mappings.
- Produces: `EvidenceJournal.open(case_dir: Path, *, max_event_bytes: int = 1_048_576) -> EvidenceJournal`; `append(kind: str, payload: Mapping[str, Any], parents: Sequence[str] = ()) -> JournalEntry`; `verify() -> JournalVerification`; `recover_interrupted_tail() -> JournalVerification`; `JournalCorruption`.

- [ ] **Step 1: Write RED tests for chain, tamper, and interrupted tail**

```python
# tests/test_evidence_journal.py
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest

from aether_re.evidence_journal import EvidenceJournal, JournalCorruption


def test_journal_chain_is_durable_and_tamper_evident(tmp_path: Path):
    journal = EvidenceJournal.open(tmp_path / "case")
    first = journal.append("case.opened", {"case_id": "case-1"})
    second = journal.append("artifact.published", {"artifact_id": "sha256:" + "a" * 64}, parents=(first.entry_hash,))
    assert second.sequence == 2 and second.previous_hash == first.entry_hash
    assert journal.verify().status == "pass"
    lines = journal.path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("case-1", "case-X")
    journal.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(JournalCorruption, match="entry_hash_mismatch"):
        journal.verify()


def test_journal_quarantines_only_truncated_final_line(tmp_path: Path):
    journal = EvidenceJournal.open(tmp_path / "case")
    journal.append("case.opened", {"case_id": "case-1"})
    with journal.path.open("ab") as handle:
        handle.write(b'{"schema":"evidence-journal-entry.v1"')
    report = journal.recover_interrupted_tail()
    assert report.status == "recovered_tail"
    assert report.entries == 1
    assert report.quarantine_path and report.quarantine_path.is_file()
    assert journal.verify().status == "pass"
```

- [ ] **Step 2: Add the concurrency review-focus test**

```python
def test_journal_serializes_concurrent_appends(tmp_path: Path):
    journal = EvidenceJournal.open(tmp_path / "case")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda index: journal.append("test.event", {"index": index}), range(40)))
    lines = [json.loads(line) for line in journal.path.read_text(encoding="utf-8").splitlines()]
    assert [item["sequence"] for item in lines] == list(range(1, 41))
    assert len({item["entry_hash"] for item in lines}) == 40
    assert journal.verify().status == "pass"
```

- [ ] **Step 3: Confirm RED**

Run: `python -m pytest tests/test_evidence_journal.py -q`

Expected: FAIL during import.

- [ ] **Step 4: Implement append and verification**

```python
# aether_re/evidence_journal.py
@dataclass(frozen=True)
class JournalEntry:
    schema: str
    sequence: int
    kind: str
    recorded_at: str
    previous_hash: str
    parents: tuple[str, ...]
    payload: Mapping[str, Any]
    entry_hash: str


@dataclass(frozen=True)
class JournalVerification:
    status: str
    entries: int
    head_hash: str
    quarantine_path: Path | None = None


class EvidenceJournal:
    SCHEMA = "evidence-journal-entry.v1"

    @classmethod
    def open(cls, case_dir: Path, *, max_event_bytes: int = 1_048_576) -> "EvidenceJournal":
        return cls(case_dir=Path(case_dir), max_event_bytes=max_event_bytes)

    def append(self, kind: str, payload: Mapping[str, Any], parents: Sequence[str] = ()) -> JournalEntry:
        return self._append_verified_entry(kind=kind, payload=payload, parents=tuple(parents))

    def verify(self) -> JournalVerification:
        return self._scan(allow_truncated_tail=False)

    def recover_interrupted_tail(self) -> JournalVerification:
        return self._recover_final_partial_line_then_scan()
```

Guard scan-and-append with one `threading.RLock`; hold a create-only `RunLock(case_dir / "journal.writer.lock")` for the journal lifetime; compute `entry_hash` over canonical fields excluding `entry_hash`; write one canonical JSON line, flush and `fsync`; then atomically write/fsync `journal.head.json`. Verification must reject sequence gaps, unknown schema, invalid parent/hash shapes, head mismatch, non-final malformed JSON, and a final malformed line unless `recover_interrupted_tail()` is explicitly invoked. Recovery writes the removed bytes create-only to `journal.tail.<sha256>.quarantine`, truncates to the last valid newline, fsyncs, and regenerates the verified head.

- [ ] **Step 5: Run journal tests twice to expose ordering flakes**

Run: `python -m pytest tests/test_evidence_journal.py -q && python -m pytest tests/test_evidence_journal.py -q`

Expected: both invocations PASS.

- [ ] **Step 6: Commit the journal slice**

```powershell
git add -- aether_re/evidence_journal.py tests/test_evidence_journal.py
git commit -m "feat(kernel): add durable hash chained journal"
```

### Task 3: Bounded Archive Inspection and Universal Intake

**Files:**
- Create: `aether_re/archive_intake.py`
- Create: `tests/test_archive_intake.py`

**Interfaces:**
- Consumes: a regular ZIP/TAR file, staging directory, `IntakeLimits`, and current nesting depth.
- Produces: `detect_archive_kind(path: Path) -> str | None`; `extract_archive_bounded(path: Path, destination: Path, *, limits: IntakeLimits, depth: int = 0) -> list[ExtractedMember]`; `ArchiveRejected`.

- [ ] **Step 1: Write hostile-container tests before implementation**

```python
# tests/test_archive_intake.py
import io
import stat
import zipfile
from pathlib import Path
import pytest

from aether_re.archive_intake import ArchiveRejected, extract_archive_bounded
from aether_re.kernel_contracts import IntakeLimits


def _zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in entries:
            archive.writestr(name, body)


def test_archive_rejects_traversal_and_duplicate_normalized_name(tmp_path: Path):
    bad = tmp_path / "bad.zip"; _zip(bad, [("../escape", b"x")])
    with pytest.raises(ArchiveRejected, match="archive_path_unsafe"):
        extract_archive_bounded(bad, tmp_path / "stage", limits=IntakeLimits())
    duplicate = tmp_path / "duplicate.zip"; _zip(duplicate, [("a/../b", b"1"), ("b", b"2")])
    with pytest.raises(ArchiveRejected, match="archive_path_unsafe|archive_member_duplicate"):
        extract_archive_bounded(duplicate, tmp_path / "stage2", limits=IntakeLimits())


def test_archive_rejects_ratio_before_commit(tmp_path: Path):
    bomb = tmp_path / "bomb.zip"; _zip(bomb, [("zeros.bin", b"0" * 100_000)])
    limits = IntakeLimits(max_files=10, max_total_bytes=200_000, max_file_bytes=200_000, max_archive_depth=1, max_compression_ratio=2, max_path_length=128)
    with pytest.raises(ArchiveRejected, match="archive_compression_ratio_exceeded"):
        extract_archive_bounded(bomb, tmp_path / "stage", limits=limits)
    assert not (tmp_path / "stage").exists()
```

Add ZIP symlink mode, TAR symlink/hardlink/device, absolute path, reserved Windows name, path-length, depth, member-count, per-file, and total-byte cases.

- [ ] **Step 2: Confirm RED**

Run: `python -m pytest tests/test_archive_intake.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement preflight-first extraction**

```python
# aether_re/archive_intake.py
@dataclass(frozen=True)
class ExtractedMember:
    relative_path: str
    path: Path
    size: int
    container_depth: int


def detect_archive_kind(path: Path) -> str | None:
    header = path.read_bytes()[:512]
    if header.startswith(b"PK\x03\x04"):
        return "zip"
    if len(header) >= 265 and header[257:263] in {b"ustar\x00", b"ustar "}:
        return "tar"
    return None


def extract_archive_bounded(path: Path, destination: Path, *, limits: IntakeLimits,
                            depth: int = 0) -> list[ExtractedMember]:
    kind = detect_archive_kind(path)
    if kind not in {"zip", "tar"}:
        raise ArchiveRejected("archive_format_unsupported")
    table = _preflight_members(path, kind=kind, limits=limits, depth=depth)
    return _extract_preflighted_members(path, kind=kind, table=table, destination=destination)
```

Build a complete normalized member table before creating `destination`; reject `PurePosixPath` absolute paths, `..`, backslashes, drive prefixes, empty names, case-folded duplicates, ADS colons, reserved Windows basenames, special/link entries, declared sizes outside budgets, and compressed ratio `uncompressed / max(compressed, 1) > max_compression_ratio`. Extract each member by bounded streaming into a new temporary sibling; validate exact written size; publish with `os.link`; remove the entire new staging directory on any exception. Nested archives are inventoried but recursion stops with `archive_depth_exceeded` once the next depth would exceed the limit.

- [ ] **Step 4: Run archive tests and existing package-boundary tests**

Run: `python -m pytest tests/test_archive_intake.py tests/test_repro_package.py tests/test_adversarial_boundaries.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the archive slice**

```powershell
git add -- aether_re/archive_intake.py tests/test_archive_intake.py
git commit -m "feat(intake): add bounded archive extraction"
```

#### Task 3B: Universal Intake Case Orchestrator

**Files:**
- Create: `aether_re/intake.py`
- Create: `tests/test_intake.py`
- Modify: `aether_re/safe_walk.py:25-44`

**Interfaces:**
- Consumes: `IntakeRequest(source: Path, case_dir: Path, authorization: AuthorizationPolicy, limits: IntakeLimits, expand_archives: bool = True)`.
- Produces: `prepare_case(request: IntakeRequest) -> IntakeResult`; `IntakeResult(case_id, source_kind, root_artifact, artifacts, inventory, manifest_path, journal_path)`; manifest schema `universal-intake-manifest.v1`.

- [ ] **Step 1: Write RED tests for files, directories, deterministic identity, and exceeded budgets**

```python
# tests/test_intake.py
import json
from pathlib import Path
import pytest

from aether_re.intake import IntakeRejected, IntakeRequest, prepare_case
from aether_re.kernel_contracts import AuthorizationPolicy, IntakeLimits


POLICY = AuthorizationPolicy.from_dict({"schema": "authorization-policy.v1", "basis": "owner", "principal": "test", "scope": ["static-analysis"]})


def test_file_intake_materializes_manifest_store_and_journal(tmp_path: Path):
    source = tmp_path / "program.bin"; source.write_bytes(b"MZ" + b"\0" * 62)
    result = prepare_case(IntakeRequest(source, tmp_path / "case", POLICY, IntakeLimits()))
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert result.source_kind == "file"
    assert manifest["schema"] == "universal-intake-manifest.v1"
    assert manifest["root_artifact"]["sha256"] == result.root_artifact.sha256
    assert result.journal_path.is_file()


def test_directory_intake_is_sorted_and_rejects_link(tmp_path: Path):
    source = tmp_path / "project"; source.mkdir()
    (source / "b.py").write_text("print(2)\n", encoding="utf-8")
    (source / "a.py").write_text("print(1)\n", encoding="utf-8")
    result = prepare_case(IntakeRequest(source, tmp_path / "case", POLICY, IntakeLimits()))
    assert [item["relative_path"] for item in result.inventory] == ["a.py", "b.py"]


def test_intake_requires_static_authorization_and_enforces_total_budget(tmp_path: Path):
    source = tmp_path / "x.bin"; source.write_bytes(b"1234")
    denied = AuthorizationPolicy.from_dict({"schema": "authorization-policy.v1", "basis": "owner", "principal": "test", "scope": ["metadata-only"]})
    with pytest.raises(IntakeRejected, match="operation_not_authorized"):
        prepare_case(IntakeRequest(source, tmp_path / "denied", denied, IntakeLimits()))
    with pytest.raises(IntakeRejected, match="intake_total_bytes_exceeded"):
        prepare_case(IntakeRequest(source, tmp_path / "limited", POLICY, IntakeLimits(max_total_bytes=3)))
```

Add cases for destination already exists, source inside destination, junction/symlink file, FIFO/special file where supported, cancellation callback, archive staging, archive rejection producing a failure journal entry, and a file modified during publication producing no success manifest.

- [ ] **Step 2: Confirm RED**

Run: `python -m pytest tests/test_intake.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Extend the safe walker with explicit diagnostics**

Add without changing `iter_files_pruned(...)`:

```python
@dataclass(frozen=True)
class WalkEntry:
    path: Path
    relative_path: str
    kind: str


def inventory_tree_bounded(root: Path, *, max_files: int, max_total_bytes: int,
                           max_file_bytes: int, max_path_length: int) -> list[WalkEntry]:
    entries: list[WalkEntry] = []
    total = 0
    for path in iter_files_pruned(root, set()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("intake_link_forbidden")
        size = path.stat(follow_symlinks=False).st_size
        if len(relative) > max_path_length or size > max_file_bytes:
            raise ValueError("intake_file_budget_exceeded")
        total += size
        entries.append(WalkEntry(path, relative, "file"))
        if len(entries) > max_files or total > max_total_bytes:
            raise ValueError("intake_total_budget_exceeded")
    return sorted(entries, key=lambda item: item.relative_path)
```

The new function must use `os.scandir`/`lstat`, sort by normalized POSIX path, never follow reparse points, reject rather than silently omit links/special files, and apply all budgets before publication.

- [ ] **Step 4: Implement case preparation as a transaction**

```python
# aether_re/intake.py
@dataclass(frozen=True)
class IntakeRequest:
    source: Path
    case_dir: Path
    authorization: AuthorizationPolicy
    limits: IntakeLimits
    expand_archives: bool = True
    cancel_check: Callable[[], bool] | None = None


@dataclass(frozen=True)
class IntakeResult:
    case_id: str
    source_kind: str
    root_artifact: ArtifactRef
    artifacts: tuple[ArtifactRef, ...]
    inventory: tuple[dict[str, Any], ...]
    manifest_path: Path
    journal_path: Path


def prepare_case(request: IntakeRequest) -> IntakeResult:
    transaction = IntakeTransaction.create(request)
    try:
        transaction.preflight()
        transaction.publish_inventory()
        return transaction.commit()
    except BaseException as exc:
        transaction.record_failure(exc)
        raise
```

Create the case directory with create-only semantics, open the journal, append `case.opened`, preflight the entire input, publish each regular file through `EvidenceStore`, append `artifact.published` only after store verification, create a canonical directory descriptor as the root artifact for directory inputs, write `manifest.json` through `write_manifest_atomic`, append `case.intake_completed` with the manifest hash, and create a detached `custody-receipt.json` using `create_custody_receipt`. On failure append `case.intake_failed` if the journal itself remains writable, leave no success manifest, and preserve quarantined diagnostics.

Derive `case_id` as `case-` plus the first 24 hex characters of `sha256_canonical({"authorization": <policy>, "root_sha256": <root>, "inventory": <sorted inventory>})`; timestamps must not affect identity.

- [ ] **Step 5: Run intake and legacy traversal/custody tests**

Run: `python -m pytest tests/test_intake.py tests/test_safe_walk.py tests/test_custody.py tests/test_evidence.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the intake slice**

```powershell
git add -- aether_re/intake.py aether_re/safe_walk.py tests/test_intake.py
git commit -m "feat(intake): prepare authorized forensic cases"
```

### Task 4: Deterministic Profile Router and Worker Lifecycle Contracts

**Files:**
- Create: `aether_re/profile_router.py`
- Create: `tests/test_profile_router.py`

**Interfaces:**
- Consumes: `IntakeResult`, leading bytes for bounded artifacts, and inventory names.
- Produces: `route_case(result: IntakeResult, store: EvidenceStore) -> ProfileDecision`; profiles `native-pe`, `native-elf`, `dotnet`, `android`, `wasm`, `jvm`, `mach-o`, `source-tree`, `archive`, `firmware-raw`, `opaque-static`, and `manual-review`.

- [ ] **Step 1: Write RED routing tests, including ambiguous/polyglot input**

```python
# tests/test_profile_router.py
from pathlib import Path

from aether_re.evidence_store import EvidenceStore
from aether_re.intake import IntakeRequest, prepare_case
from aether_re.kernel_contracts import AuthorizationPolicy, EpistemicState, IntakeLimits
from aether_re.profile_router import route_case


POLICY = AuthorizationPolicy.from_dict({"schema": "authorization-policy.v1", "basis": "owner", "principal": "test", "scope": ["static-analysis"]})


def _route(tmp_path: Path, name: str, body: bytes):
    target = tmp_path / name; target.write_bytes(body)
    result = prepare_case(IntakeRequest(target, tmp_path / (name + ".case"), POLICY, IntakeLimits()))
    return route_case(result, EvidenceStore(result.manifest_path.parent))


def test_router_uses_content_not_extension(tmp_path: Path):
    decision = _route(tmp_path, "renamed.txt", b"\x00asm\x01\x00\x00\x00")
    assert decision.profile_id == "wasm"
    assert decision.pipeline == ("wasm-static",)
    assert decision.epistemic_state is EpistemicState.EXACT


def test_router_abstains_on_conflicting_strong_signatures(tmp_path: Path):
    decision = _route(tmp_path, "polyglot.bin", b"MZ" + b"\x00" * 126 + b"\x00asm\x01\x00\x00\x00")
    assert decision.profile_id == "manual-review"
    assert decision.epistemic_state is EpistemicState.UNKNOWN
    assert len(decision.candidates) >= 2
```

- [ ] **Step 2: Confirm RED**

Run: `python -m pytest tests/test_profile_router.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement immutable detection rules and decision schema**

```python
# aether_re/profile_router.py
@dataclass(frozen=True)
class ProfileCandidate:
    profile_id: str
    strength: int
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class ProfileDecision:
    schema: str
    profile_id: str
    pipeline: tuple[str, ...]
    candidates: tuple[ProfileCandidate, ...]
    epistemic_state: EpistemicState
    limitations: tuple[str, ...]


def route_case(result: IntakeResult, store: EvidenceStore) -> ProfileDecision:
    candidates = tuple(sorted(_collect_candidates(result, store), key=lambda item: (-item.strength, item.profile_id)))
    strong = tuple(item for item in candidates if item.strength >= 90)
    if len(strong) > 1 and _contains_incompatible_profiles(strong):
        return ProfileDecision("profile-decision.v1", "manual-review", (), candidates, EpistemicState.UNKNOWN, ("conflicting strong signatures",))
    selected = strong[0] if strong else (candidates[0] if candidates else None)
    if selected is None:
        return ProfileDecision("profile-decision.v1", "opaque-static", ("opaque-static",), (), EpistemicState.UNKNOWN, ("no certified profile matched",))
    return _decision_for(selected, candidates)
```

Use bounded signatures and structural corroboration: PE requires `MZ` plus in-range `PE\0\0`; ELF uses `\x7fELF`; WASM uses `\0asm` at offset zero; Mach-O uses known thin/fat magics; ZIP-based profiles inspect member names from intake inventory (`AndroidManifest.xml` plus `classes.dex`, `.class`/`META-INF/MANIFEST.MF`, CLR metadata only after PE parsing); source-tree requires recognized source suffixes plus text-decodable samples. Two strong, incompatible candidates produce `manual-review`; weak/no match produces `opaque-static`. Never use extension as sufficient evidence.

- [ ] **Step 4: Add compatibility coverage for every profile and malformed headers**

Add parameterized cases for truncated PE, ELF class/machine, valid APK member set, JAR member set, .NET PE without CLR header, Mach-O, source directory, generic ZIP, raw high-entropy bytes, and extension/content disagreement. Assert candidate evidence contains offsets/member names and no decision claims `universal=True`.

- [ ] **Step 5: Run router plus existing triage/profile tests**

Run: `python -m pytest tests/test_profile_router.py tests/test_profile_scope.py tests/test_pe_structure.py tests/test_elf_structure.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the router slice**

```powershell
git add -- aether_re/profile_router.py tests/test_profile_router.py
git commit -m "feat(router): route profiles with explicit abstention"
```

#### Task 4B: Worker Lifecycle Contracts and Hostile Output Validation

**Files:**
- Modify: `aether_re/contracts.py:1-72`
- Create: `tests/test_worker_contracts_v2.py`

**Interfaces:**
- Consumes: capability/probe, execution plan, and worker result mappings.
- Produces: `validate_worker_probe(value: Mapping[str, Any]) -> WorkerProbe`; `validate_worker_plan(value: Mapping[str, Any]) -> WorkerPlan`; `validate_worker_result(value: Mapping[str, Any], *, plan: WorkerPlan, max_output_bytes: int) -> WorkerResult`; `WorkerAdapter` protocol with `probe`, `supports`, `plan`, `run`, `normalize`, `validate`, and `cleanup`; existing `validate_adapter_result(...)` unchanged.

- [ ] **Step 1: Write RED tests for lifecycle and fake success**

```python
# tests/test_worker_contracts_v2.py
import pytest

from aether_re.contracts import ContractViolation, validate_worker_plan, validate_worker_result


def _plan():
    return validate_worker_plan({
        "schema": "worker-plan.v1", "worker": "ghidra", "worker_version": "11.4",
        "input_artifact_id": "sha256:" + "a" * 64,
        "command": ["analyzeHeadless", "<workspace>", "case"],
        "network": False, "timeout_s": 120, "memory_mb": 2048,
        "disk_mb": 4096, "processes": 8,
    })


def test_worker_result_rejects_success_without_evidence():
    with pytest.raises(ContractViolation, match="success_without_evidence"):
        validate_worker_result({
            "schema": "worker-result.v1", "worker": "ghidra", "state": "succeeded",
            "plan_sha256": _plan().plan_sha256, "evidence": [], "losses": [],
            "stdout": "", "stderr": "", "returncode": 0,
        }, plan=_plan(), max_output_bytes=4096)


def test_worker_result_distinguishes_timeout_oom_cancel_and_malformed():
    plan = _plan()
    for state in ("timed_out", "oom", "cancelled", "malformed_output"):
        result = validate_worker_result({
            "schema": "worker-result.v1", "worker": "ghidra", "state": state,
            "plan_sha256": plan.plan_sha256, "evidence": [], "losses": [state],
            "stdout": "", "stderr": state, "returncode": None,
        }, plan=plan, max_output_bytes=4096)
        assert result.state == state
```

- [ ] **Step 2: Confirm RED while proving v1 stays green**

Run: `python -m pytest tests/test_worker_contracts_v2.py tests/test_contracts.py -q`

Expected: new tests FAIL on missing symbols; `tests/test_contracts.py` remains PASS.

- [ ] **Step 3: Add the v2 immutable dataclasses and protocol**

```python
@runtime_checkable
class WorkerAdapter(Protocol):
    def probe(self) -> Mapping[str, Any]: raise NotImplementedError
    def supports(self, profile_id: str, architecture: str) -> bool: raise NotImplementedError
    def plan(self, artifact: ArtifactRef, profile_id: str) -> Mapping[str, Any]: raise NotImplementedError
    def run(self, plan: "WorkerPlan") -> Mapping[str, Any]: raise NotImplementedError
    def normalize(self, result: "WorkerResult") -> Sequence[Mapping[str, Any]]: raise NotImplementedError
    def validate(self, result: "WorkerResult") -> None: raise NotImplementedError
    def cleanup(self) -> None: raise NotImplementedError


WORKER_STATES = frozenset({"succeeded", "partial", "failed", "timed_out", "oom", "cancelled", "malformed_output", "unavailable", "skipped"})
```

`WorkerProbe` must bind name/version/executable SHA-256/license/capabilities; `WorkerPlan` must hash its canonical form and require network `False` for this static slice plus positive bounded resources; `WorkerResult` must match `plan_sha256`, cap UTF-8 stdout/stderr and total evidence JSON bytes, reject unknown schemas/fields, and permit `succeeded` only with at least one strict evidence envelope. Keep the v1 functions byte-for-byte behaviorally compatible.

- [ ] **Step 4: Add command mutation and oversized-output tests**

Assert that recomputing a plan after changing any command/resource changes `plan_sha256`, that a result bound to the old hash fails `plan_hash_mismatch`, and that output over `max_output_bytes` fails `worker_output_budget_exceeded` before JSON expansion.

- [ ] **Step 5: Run contract tests**

Run: `python -m pytest tests/test_worker_contracts_v2.py tests/test_contracts.py tests/test_process.py tests/test_process_cleanup.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the worker-contract slice**

```powershell
git add -- aether_re/contracts.py tests/test_worker_contracts_v2.py
git commit -m "feat(workers): add versioned lifecycle contracts"
```

### Task 5: Evidence Envelopes, Pipeline Integration, and CLI

**Files:**
- Modify: `aether_re/evidence_contract.py:10-104`
- Create: `tests/test_kernel_evidence_contract.py`

**Interfaces:**
- Consumes: kernel evidence envelope mappings plus an optional intake manifest.
- Produces: `validate_kernel_evidence(records: list[dict[str, Any]], *, manifest: dict[str, Any]) -> dict[str, Any]`; legacy `validate_evidence_records(...)` unchanged.

- [ ] **Step 1: Write RED evidence-binding tests**

```python
# tests/test_kernel_evidence_contract.py
from aether_re.evidence_contract import validate_kernel_evidence


def test_kernel_evidence_requires_artifact_derivation_and_epistemic_rules():
    digest = "a" * 64
    manifest = {"schema": "universal-intake-manifest.v1", "artifacts": [{"artifact_id": "sha256:" + digest, "sha256": digest}]}
    record = {
        "schema": "kernel-evidence.v1", "evidence_id": "ev-1", "case_id": "case-1",
        "artifact_id": "sha256:" + digest, "artifact_sha256": digest,
        "producer": {"name": "triage", "version": "1", "release": "builtin"},
        "method": "magic", "location": {"offset": 0, "length": 4},
        "epistemic_state": "EXACT", "confidence": None,
        "derivation_parents": ["sha256:" + digest], "limitations": [], "losses": [],
    }
    assert validate_kernel_evidence([record], manifest=manifest)["status"] == "valid"
    record["artifact_sha256"] = "b" * 64
    report = validate_kernel_evidence([record], manifest=manifest)
    assert report["status"] == "invalid"
    assert any(error["code"] == "artifact_manifest_mismatch" for error in report["errors"])
```

- [ ] **Step 2: Confirm RED**

Run: `python -m pytest tests/test_kernel_evidence_contract.py tests/test_evidence_contract.py -q`

Expected: new test FAILS on missing function; legacy tests PASS.

- [ ] **Step 3: Implement v1 kernel envelope validation**

Validate exact allowed fields, unique evidence IDs, case ID, manifest-bound artifact ID/hash, producer name/version/release, non-negative bounded offset/length, parent IDs, epistemic/confidence rules from `kernel_contracts.py`, list-shaped limitations/losses, and canonical serialized size at most 1 MiB per record. Return `evidence-kernel-validation.v1` with counts and error codes; do not mutate or coerce input values.

- [ ] **Step 4: Add rejection tests for unknown field, bad span, duplicated ID, NaN, unsupported confidence, and missing parent**

Use a parameterized test whose expected codes are `unknown_field`, `location_invalid`, `duplicate_evidence_id`, `confidence_invalid`, `confidence_forbidden`, and `derivation_parent_missing`.

- [ ] **Step 5: Run both evidence generations**

Run: `python -m pytest tests/test_kernel_evidence_contract.py tests/test_evidence_contract.py tests/test_claims.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the bridge**

```powershell
git add -- aether_re/evidence_contract.py tests/test_kernel_evidence_contract.py
git commit -m "feat(kernel): validate manifest bound evidence envelopes"
```

#### Task 5B: Integrate Intake and Routing into the Existing Static Pipeline

**Files:**
- Modify: `aether_re/pipeline.py:20-28,185-511`
- Modify: `aether_re/models.py` at the `AnalysisReport` dataclass
- Create: `tests/test_pipeline_kernel.py`

**Interfaces:**
- Consumes: existing `run_megazord(target, out_dir, use_adapters, deep)` calls.
- Produces: backward-compatible `AnalysisReport` plus `case_id`, `intake_manifest`, `root_artifact_id`, `profile_decision`, and `evidence_journal`; all native/adapters read the immutable store object.

- [ ] **Step 1: Write a RED integration test that swaps the original after intake**

```python
# tests/test_pipeline_kernel.py
import json
from pathlib import Path

from aether_re.pipeline import run_megazord


def test_pipeline_analyzes_kernel_object_and_binds_manifest(tmp_path: Path, monkeypatch):
    target = tmp_path / "sample.bin"; target.write_bytes(b"MZ" + b"\0" * 126)
    report = run_megazord(target, out_dir=tmp_path / "run", use_adapters=False, deep=False)
    manifest = json.loads((tmp_path / "run" / "intake" / "manifest.json").read_text(encoding="utf-8"))
    assert report.case_id == manifest["case_id"]
    assert report.root_artifact_id == manifest["root_artifact"]["artifact_id"]
    assert report.profile_decision["profile_id"] in {"native-pe", "manual-review"}
    assert Path(report.evidence_journal).is_file()
    assert report.target_sha256 == manifest["root_artifact"]["sha256"]
```

Add a spy around `triage.run_triage` and every enabled adapter asserting the path is beneath `out_dir/intake/objects/sha256`, not the original target.

- [ ] **Step 2: Confirm RED against the current pipeline**

Run: `python -m pytest tests/test_pipeline_kernel.py -q`

Expected: FAIL because `AnalysisReport` lacks the kernel fields and the pipeline has no intake directory.

- [ ] **Step 3: Add backward-compatible report fields**

Add defaulted fields to `AnalysisReport`:

```python
case_id: str = ""
intake_manifest: str = ""
root_artifact_id: str = ""
profile_decision: dict[str, Any] = field(default_factory=dict)
evidence_journal: str = ""
```

- [ ] **Step 4: Replace direct snapshot creation with kernel preparation**

At the existing `checkpoint("intake")` boundary, construct an owner/static authorization policy for the already-authorized local CLI invocation, call `prepare_case(IntakeRequest(target, out_dir / "intake", policy, IntakeLimits(max_file_bytes=512 * 1024 * 1024)))`, open its store, route it, and set `analysis_target = store.resolve(intake.root_artifact)`. Preserve the existing pre/post original target hash comparison, disk guard, checkpoints, cache key, lock, and `input.snapshot` compatibility by creating `input.snapshot` as a verified hard link/copy from the store object only if existing consumers require that filename.

Serialize the complete profile decision into the report, include all kernel paths/IDs in `manifest.json` metadata, and append `analysis.completed` only after final report/manifest publication and their hashes are known. If final publication fails, append `analysis.failed`; never append completion first.

- [ ] **Step 5: Test failure ordering and original mutation**

Add tests that monkeypatch final manifest write to raise `OSError("disk_full")` and assert the journal contains `analysis.failed` but no `analysis.completed`; mutate the original after intake and assert the current `source_changed_during_analysis` guard still rejects publication.

- [ ] **Step 6: Run pipeline compatibility tests**

Run: `python -m pytest tests/test_pipeline_kernel.py tests/test_pipeline_guards.py tests/test_identity.py tests/test_project.py tests/test_cache.py -q`

Expected: PASS.

- [ ] **Step 7: Commit the pipeline integration**

```powershell
git add -- aether_re/pipeline.py aether_re/models.py tests/test_pipeline_kernel.py
git commit -m "feat(pipeline): analyze immutable kernel snapshots"
```

#### Task 5C: Explicit Intake CLI and Machine-Readable Failure States

**Files:**
- Modify: `megazord.py` imports, command handlers, and `main()` parser
- Create: `tests/test_intake_cli.py`

**Interfaces:**
- Consumes: `python megazord.py intake SOURCE --case-dir DIR --authorization FILE [budget flags]`.
- Produces: exit `0` plus JSON manifest path on success; exit `2` plus `intake-cli-result.v1` JSON on contract/input rejection; exit `1` only for unexpected internal failure, without traceback by default.

- [ ] **Step 1: Write RED CLI tests**

```python
# tests/test_intake_cli.py
import json
from argparse import Namespace
from pathlib import Path

from megazord import cmd_intake


def test_intake_cli_requires_explicit_authorization(tmp_path: Path):
    source = tmp_path / "x.bin"; source.write_bytes(b"abc")
    out = tmp_path / "result.json"
    code = cmd_intake(Namespace(source=str(source), case_dir=str(tmp_path / "case"), authorization=str(tmp_path / "missing.json"), result=str(out), no_expand_archives=False, max_files=10, max_total_bytes=100, max_file_bytes=100, max_archive_depth=1, max_compression_ratio=20, max_path_length=128))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "rejected"
    assert report["error"] == "authorization_unreadable"
```

Add success, invalid JSON, authorization lacking `static-analysis`, invalid boolean-as-integer budget through direct handler call, existing destination, and malicious archive cases. Assert stderr/result never contain a traceback or target bytes.

- [ ] **Step 2: Confirm RED**

Run: `python -m pytest tests/test_intake_cli.py -q`

Expected: FAIL on missing `cmd_intake`.

- [ ] **Step 3: Implement the handler and parser**

```python
def cmd_intake(args: argparse.Namespace) -> int:
    result_path = Path(args.result)
    try:
        policy = AuthorizationPolicy.from_dict(json.loads(Path(args.authorization).read_text(encoding="utf-8")))
        limits = IntakeLimits.from_dict({
            "max_files": args.max_files, "max_total_bytes": args.max_total_bytes,
            "max_file_bytes": args.max_file_bytes, "max_archive_depth": args.max_archive_depth,
            "max_compression_ratio": args.max_compression_ratio, "max_path_length": args.max_path_length,
        })
        intake = prepare_case(IntakeRequest(Path(args.source), Path(args.case_dir), policy, limits, not args.no_expand_archives))
        report = {"schema": "intake-cli-result.v1", "status": "complete", "case_id": intake.case_id, "manifest": str(intake.manifest_path)}
        code = 0
    except (OSError, json.JSONDecodeError, ContractError, IntakeRejected) as exc:
        report = {"schema": "intake-cli-result.v1", "status": "rejected", "error": normalize_intake_error(exc)}
        code = 2
    write_json_atomic(report, result_path)
    return code
```

Add parser flags with defaults equal to `IntakeLimits`; `--authorization` and `--result` are required. `normalize_intake_error` maps exception classes to bounded stable codes and never includes arbitrary paths/content.

- [ ] **Step 4: Run handler and subprocess tests**

Run: `python -m pytest tests/test_intake_cli.py tests/test_cli_encoding.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the CLI slice**

```powershell
git add -- megazord.py tests/test_intake_cli.py
git commit -m "feat(cli): expose authorized universal intake"
```

### Task 6: Chaos, Replay, Documentation, and F02 Acceptance Gate

**Files:**
- Create: `tests/test_kernel_chaos.py`
- Create: `tests/test_kernel_replay.py`
- Create: `docs/EVIDENCE_KERNEL.md`
- Modify: `README.md` command/capability section only

**Interfaces:**
- Consumes: a completed or interrupted case directory.
- Produces: reproducible verification commands and an `F02` evidence bundle whose claims remain local/non-WORM.

- [ ] **Step 1: Write chaos tests before acceptance code/docs**

```python
# tests/test_kernel_chaos.py
from pathlib import Path
import pytest

import json
import aether_re.evidence_store as store_module
from aether_re.evidence_journal import EvidenceJournal, JournalCorruption
from aether_re.intake import IntakeRejected, IntakeRequest, prepare_case
from aether_re.kernel_contracts import AuthorizationPolicy, IntakeLimits


def test_disk_failure_never_acknowledges_unpublished_object(tmp_path: Path, monkeypatch):
    source = tmp_path / "sample.bin"; source.write_bytes(b"evidence")
    policy = AuthorizationPolicy.from_dict({"schema": "authorization-policy.v1", "basis": "owner", "principal": "test", "scope": ["static-analysis"]})
    def disk_full(_handle):
        raise OSError("disk_full")
    monkeypatch.setattr(store_module, "_fsync_file", disk_full)
    case_dir = tmp_path / "case"
    with pytest.raises((OSError, IntakeRejected), match="disk_full"):
        prepare_case(IntakeRequest(source, case_dir, policy, IntakeLimits()))
    object_files = [path for path in (case_dir / "objects").rglob("*") if path.is_file()] if (case_dir / "objects").exists() else []
    assert object_files == []
    events = [json.loads(line)["kind"] for line in (case_dir / "journal.jsonl").read_text(encoding="utf-8").splitlines()]
    assert "artifact.published" not in events


def test_interior_journal_corruption_cannot_be_recovered_as_tail(tmp_path: Path):
    journal = EvidenceJournal.open(tmp_path / "case")
    journal.append("one", {"n": 1}); journal.append("two", {"n": 2})
    data = journal.path.read_bytes().replace(b'"n":1', b'"n":9')
    journal.path.write_bytes(data)
    with pytest.raises(JournalCorruption):
        journal.recover_interrupted_tail()
```

Also add cancellation before copy, cancellation mid-copy, simulated `MemoryError`, read-only case directory, corrupted head sidecar, missing object, and replay after clean process reopen.

- [ ] **Step 2: Write deterministic replay tests**

```python
# tests/test_kernel_replay.py
def test_clean_replay_recomputes_every_hash_and_decision(tmp_path: Path):
    first = build_case_fixture(tmp_path / "first")
    replay = replay_case(first.manifest_path, tmp_path / "replay")
    assert replay.status == "pass"
    assert replay.root_sha256 == first.root_artifact.sha256
    assert replay.profile_decision_hash == first.profile_decision_hash
    assert replay.journal_verification.status == "pass"
```

Implement `verify_case(case_dir: Path) -> CaseVerification` and `replay_case(manifest_path: Path, destination: Path) -> ReplayReport` in `aether_re/intake.py`. Replay reads only store objects named by the manifest, verifies custody/journal/object hashes first, reruns routing into a new create-only directory, and compares canonical decision/inventory hashes; it does not execute adapters or target bytes.

- [ ] **Step 3: Run chaos/replay tests and confirm failures identify missing behavior**

Run: `python -m pytest tests/test_kernel_chaos.py tests/test_kernel_replay.py -q`

Expected before the acceptance implementation: failures on the exact unimplemented verification/replay boundaries, not collection errors from misspelled interfaces.

- [ ] **Step 4: Complete verification/replay helpers and make focused tests green**

Run: `python -m pytest tests/test_kernel_chaos.py tests/test_kernel_replay.py tests/test_evidence_journal.py tests/test_intake.py -q`

Expected: PASS.

- [ ] **Step 5: Write the operator document with exact commands and limitation language**

`docs/EVIDENCE_KERNEL.md` must include:

```text
Create case:
python megazord.py intake <SOURCE> --case-dir <NEW_DIR> --authorization <POLICY.json> --result <RESULT.json>

Verify/replay (Python API in this slice):
verify_case(Path(<CASE_DIR>))
replay_case(Path(<CASE_DIR>/manifest.json), Path(<NEW_REPLAY_DIR>))

Custody statement:
This package proves local hash-chain integrity only. external_anchor=false; it is not WORM, notarization, semantic truth, or proof that the analyzed bytes were lawfully obtained.
```

Document the directory layout, every schema/version, all default budgets, authorization example, event ordering, recovery/quarantine procedure, profile abstention, worker lifecycle, and incident response for corruption/disk-full/cancellation. Update the README to link this document and list only the profiles proven by tests.

- [ ] **Step 6: Run the complete clean gate**

Run: `python -m pytest -q`

Expected: all tests PASS except pre-existing explicitly documented environment skips; zero failures/errors and no newly skipped kernel/intake test.

- [ ] **Step 7: Produce machine-readable F02 evidence without declaring the entire project complete**

Run:

```powershell
New-Item -ItemType Directory -Force output\f02_kernel | Out-Null
python -m pytest tests/test_kernel_contracts.py tests/test_evidence_store.py tests/test_evidence_journal.py tests/test_archive_intake.py tests/test_intake.py tests/test_profile_router.py tests/test_worker_contracts_v2.py tests/test_kernel_evidence_contract.py tests/test_pipeline_kernel.py tests/test_intake_cli.py tests/test_kernel_chaos.py tests/test_kernel_replay.py --junitxml=output/f02_kernel/junit.xml -q 2>&1 | Tee-Object output/f02_kernel/pytest.log
python megazord.py phase-gates --input output/f02_kernel/f02_gate_input.json --root output/f02_kernel --out output/f02_kernel/f02_gate_report.json
```

Before the second command, generate `f02_gate_input.json` from the actual JUnit/log/document hashes using the existing `phase-gates` schema; do not hand-enter a passing status. Expected: kernel test command exits `0`; gate status is whatever the existing evaluator proves. If any required chaos/replay evidence is absent, F02 remains partial and the report must say so.

- [ ] **Step 8: Commit the acceptance slice**

```powershell
git add -- aether_re/intake.py tests/test_kernel_chaos.py tests/test_kernel_replay.py docs/EVIDENCE_KERNEL.md README.md
git commit -m "test(kernel): prove recovery replay and intake boundaries"
```

## Final Verification Checklist

- [ ] Run `python -m pytest -q` and record exact passed/failed/error/skipped counts.
- [ ] Run `python -m pytest tests/test_evidence.py tests/test_custody.py tests/test_evidence_contract.py tests/test_contracts.py tests/test_profile_scope.py tests/test_pipeline_guards.py -q` to prove backward compatibility.
- [ ] Search the implementation for target execution introduced by this slice: `git diff --unified=0 HEAD~11 -- aether_re megazord.py | Select-String -Pattern 'subprocess|Popen|os\.system|shell=True'`; expected result is no new execution path in kernel/intake/router code.
- [ ] Verify every case artifact referenced by `manifest.json` with `verify_case(...)` and verify the journal head after reopening in a new Python process.
- [ ] Confirm an ambiguous artifact produces `manual-review`/`UNKNOWN` and an unsupported artifact produces `opaque-static`, never a universal support claim.
- [ ] Confirm local custody reports `external_anchor=False` and documentation repeats the non-WORM limitation.
- [ ] Confirm `git status --short` contains the pre-existing user changes plus only this plan's intentional implementation files; never stage unrelated files.
- [ ] Update the Codebase Knowledge Graph after implementation with `index_repository(repo_path="D:/AetherRE_Megazord", mode="moderate")`, then trace `run_megazord` to prove analyzers consume the kernel object path.

## Scope Boundary After This Plan

This plan can make F02 materially testable and establishes the common contracts required by all later adapters. It does not itself complete managed/mobile/WASM adapters, native IR/graph upgrades, the real-VM laboratory, blind holdout calibration, all F00-F12 gates, or independent review. Those remain separate plans and must not be reported as complete because this kernel slice passes.
