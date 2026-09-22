# Dynamic Lab, Validation, and Certified Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the production-grade real-VM laboratory, authorized blind corpus, calibrated validation, adversarial/chaos campaigns, clean replay, and independent release certification required to close gates F00-F12 without converting declarations into proof.

**Architecture:** Extend the existing fail-closed `lab_policy`, `metrics`, `repro_package`, `homologation`, and `phase_gates` modules with focused components. A Hyper-V worker controls a disposable Windows guest through PowerShell Direct, while all target execution remains inside the guest; every run emits a hash-bound attestation consumed by the existing runtime-proof validator. A release coordinator admits only sealed, family-disjoint corpus results and independently signed review evidence before asking `evaluate_phase_gates` for the final verdict.

**Tech Stack:** Python 3.11+, pytest, standard-library `dataclasses`, `hashlib`, `hmac`, `json`, `pathlib`, `statistics`, `subprocess`; Windows PowerShell 5.1+/PowerShell 7; Hyper-V PowerShell module and PowerShell Direct for the first real-VM provider.

**Spec:** `docs/superpowers/specs/2026-09-22-universal-forensic-reconstruction-design.md`

## Global Constraints

- Only owned, public-license-compatible, or explicitly authorized artifacts may enter any corpus or dynamic run.
- Static analysis remains the default; target execution is forbidden on the host and is admitted only after a real disposable VM passes F08.
- Guest networking is disconnected by default; writable project mounts and host execution are always forbidden.
- Every proof artifact is canonical JSON, content-addressed with SHA-256, bounded by explicit event/file/byte/time/memory limits, and written atomically.
- `EXACT`, `VERIFIED_RECONSTRUCTION`, `PROBABILISTIC_INFERENCE`, `HYPOTHESIS`, and `UNKNOWN` are the only epistemic states; inability to prove a claim produces `UNKNOWN` or a non-passing gate.
- A profile or gate is `QUITADA` only with implementation, integration, passing tests, hashed evidence, and independent review; missing evidence is `NAO_COMPROVADA`.
- Calibration, development, blind holdout, adversarial, and authorized-real partitions are hash-sealed; identity, evidence, or family leakage invalidates certification.
- No tool, VM image, corpus, dependency, or rule set is promoted without an exact version/commit, digest, license record, and reproducible acquisition record.
- GPL/AGPL tools remain out-of-process unless a written license decision explicitly approves another integration form.
- A clean-install replay must use a locked dependency set and must reproduce the release evidence hashes in a new environment.
- The final release stays `partial` while any F00-F12 row is not `QUITADA`, any integrity error exists, or the independent review is missing/invalid.

## Review Focus

- A stale or forged guest proof with valid-looking fields must be rejected when its nonce, target hash, checkpoint identity, collector identity, or signature is not bound to the issued run lease; Task 1 pins this.
- A VM command that succeeds while rollback, network disconnection, or guest heartbeat fails must yield `refused`/`failed`, never `verified`; Tasks 2 and 3 pin this.
- Duplicate artifacts renamed across corpus partitions, related build variants, or shared evidence identifiers must invalidate the blind split; Task 3 pins this.
- Empty/imbalanced strata and abstentions must remain in metric denominators and confidence intervals rather than being silently dropped; Task 4 pins this.
- Tampered replay members, malicious report strings, interrupted journals, active run locks, and reviewer self-approval must block release; Tasks 6-9 pin these cases.

## Locked File Structure

| Path | Responsibility |
|---|---|
| `aether_re/vm_attestation.py` | Run leases, canonical guest attestations, signature verification, replay protection |
| `aether_re/vm_lab.py` | Provider-neutral VM lifecycle protocol and fail-closed dynamic-run coordinator |
| `aether_re/vm_hyperv.py` | Concrete Hyper-V/PowerShell Direct provider; no policy decisions |
| `aether_re/corpus_registry.py` | Authorization records, artifact/family identities, sealed partitions |
| `aether_re/certification_metrics.py` | Stratified metrics, Wilson intervals, calibration, baseline deltas, sufficiency rules |
| `aether_re/validation_campaign.py` | Deterministic chaos and red-team campaign runner with bounded cases |
| `aether_re/release_replay.py` | Clean-install recipe, environment fingerprint, replay and hash comparison |
| `aether_re/release_certification.py` | F00-F12 evidence matrix, independent review attestation, final release verdict |
| `tools/qualify_hyperv_lab.py` | Operator entry point for a benign real-VM qualification run |
| `tools/run_validation_campaign.py` | Offline campaign CLI |
| `tools/run_release_replay.py` | Clean-environment replay CLI |
| `tools/certify_release.py` | Final fail-closed certification CLI |
| `tests/fixtures/release/benign_probe.ps1` | Owned non-malicious guest fixture used only for VM qualification |
| `tests/test_vm_attestation.py` | Lease/attestation unit and adversarial tests |
| `tests/test_vm_lab.py` | Lifecycle, rollback, cancellation, timeout, and cleanup tests |
| `tests/test_vm_hyperv.py` | Exact PowerShell command and fail-closed provider tests |
| `tests/test_corpus_registry.py` | Authorization and sealed split tests |
| `tests/test_certification_metrics.py` | Metric/calibration/baseline tests |
| `tests/test_validation_campaign.py` | Chaos/red-team orchestration tests |
| `tests/test_release_replay.py` | Clean replay and tamper tests |
| `tests/test_release_certification.py` | Independent review and F00-F12 aggregation tests |
| `docs/DYNAMIC_LAB_RUNBOOK.md` | Safe real-VM provisioning, qualification, incident, and teardown procedure |
| `docs/RELEASE_CERTIFICATION.md` | Exact evidence contract and independent-review procedure |

---

### Task 1: Cryptographically Bound VM Run Lease and Guest Attestation

**Files:**
- Create: `aether_re/vm_attestation.py`
- Create: `tests/test_vm_attestation.py`
- Modify: `aether_re/lab_policy.py:46-165`
- Modify: `tests/test_lab_policy.py:64-206`

**Interfaces:**
- Consumes: existing `validate_runtime_proof(proof: dict[str, Any], *, policy: LabPolicy | None = None, max_events: int = 100_000) -> dict[str, Any]`.
- Produces: `issue_run_lease(*, run_id: str, snapshot_id: str, target_sha256: str, collector_sha256: str, issued_at: str, expires_at: str, nonce: str) -> dict[str, Any]`; `sign_attestation(attestation: dict[str, Any], *, key: bytes) -> dict[str, Any]`; `verify_attestation(attestation: Any, *, lease: dict[str, Any], key: bytes, now: datetime, max_events: int = 100_000) -> dict[str, Any]`.
- Invariant: canonical signature input is UTF-8 JSON with `sort_keys=True`, `separators=(",", ":")`, and the `signature` member removed; signature is lowercase HMAC-SHA256 hex.

- [ ] **Step 1: Write failing lease-binding tests**

```python
from datetime import datetime, timezone
from aether_re.vm_attestation import issue_run_lease, sign_attestation, verify_attestation

KEY = b"qualification-key-with-32-bytes!!"

def _lease():
    return issue_run_lease(
        run_id="run-001", snapshot_id="clean-001", target_sha256="a" * 64,
        collector_sha256="b" * 64, issued_at="2026-09-22T12:00:00Z",
        expires_at="2026-09-22T12:10:00Z", nonce="nonce-001",
    )

def _attestation():
    return sign_attestation({
        "schema": "dynamic-lab-attestation.v1", "run_id": "run-001",
        "snapshot_id": "clean-001", "target_sha256": "a" * 64,
        "collector_sha256": "b" * 64, "nonce": "nonce-001",
        "started_at": "2026-09-22T12:01:00Z", "ended_at": "2026-09-22T12:02:00Z",
        "rollback_verified": True, "network_isolated": True,
        "collector_heartbeat": True, "timeout_s": 60, "memory_limit_mb": 512,
        "target_identity": {"name": "benign_probe.ps1"},
        "events": [{"seq": 0, "kind": "process_start"}, {"seq": 1, "kind": "process_exit"}],
    }, key=KEY)

def test_attestation_is_bound_to_lease_and_signature():
    report = verify_attestation(_attestation(), lease=_lease(), key=KEY,
                                now=datetime(2026, 9, 22, 12, 3, tzinfo=timezone.utc))
    assert report["status"] == "verified"
    assert report["binding"]["run_id"] is True
    assert report["binding"]["target_sha256"] is True

def test_attestation_rejects_replay_expiry_and_field_tamper():
    document = _attestation()
    document["snapshot_id"] = "different"
    report = verify_attestation(document, lease=_lease(), key=KEY,
                                now=datetime(2026, 9, 22, 12, 11, tzinfo=timezone.utc))
    codes = {error["code"] for error in report["errors"]}
    assert {"signature_invalid", "snapshot_id_mismatch", "lease_expired"} <= codes
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m pytest tests/test_vm_attestation.py -q`

Expected: collection fails with `ModuleNotFoundError: No module named 'aether_re.vm_attestation'`.

- [ ] **Step 3: Implement strict lease and signature validation**

```python
def issue_run_lease(*, run_id: str, snapshot_id: str, target_sha256: str,
                    collector_sha256: str, issued_at: str, expires_at: str,
                    nonce: str) -> dict[str, Any]:
    values = {"run_id": run_id, "snapshot_id": snapshot_id, "target_sha256": target_sha256,
              "collector_sha256": collector_sha256, "issued_at": issued_at,
              "expires_at": expires_at, "nonce": nonce}
    errors = _validate_lease_fields(values)
    if errors:
        raise ValueError(";".join(errors))
    return {"schema": "dynamic-lab-lease.v1", **values}

def sign_attestation(attestation: dict[str, Any], *, key: bytes) -> dict[str, Any]:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("attestation_key_too_short")
    signed = dict(attestation)
    signed.pop("signature", None)
    signed["signature"] = hmac.new(key, _canonical_bytes(signed), hashlib.sha256).hexdigest()
    return signed

def verify_attestation(attestation: Any, *, lease: dict[str, Any], key: bytes,
                       now: datetime, max_events: int = 100_000) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    if not isinstance(attestation, dict):
        return {"schema": "dynamic-lab-attestation-verification.v1", "status": "invalid",
                "binding": {}, "runtime_validation": {},
                "errors": [{"code": "attestation_must_be_object"}]}
    unsigned = dict(attestation)
    signature = unsigned.pop("signature", None)
    expected = hmac.new(key, _canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        errors.append({"code": "signature_invalid"})
    binding: dict[str, bool] = {}
    for field in ("run_id", "snapshot_id", "target_sha256", "collector_sha256", "nonce"):
        binding[field] = attestation.get(field) == lease.get(field)
        if not binding[field]:
            errors.append({"code": f"{field}_mismatch"})
    expires_at = _parse_utc(lease.get("expires_at"), field="expires_at", errors=errors)
    if expires_at is not None and now > expires_at:
        errors.append({"code": "lease_expired"})
    runtime = validate_runtime_proof(attestation, max_events=max_events,
                                     expected_run_id=lease.get("run_id"),
                                     expected_target_sha256=lease.get("target_sha256"))
    errors.extend(runtime.get("errors", []))
    return {"schema": "dynamic-lab-attestation-verification.v1",
            "status": "verified" if not errors and runtime.get("status") == "verified" else "invalid",
            "binding": binding, "runtime_validation": runtime, "errors": errors}
```

Replace the ellipsis with explicit validation branches returning schema `dynamic-lab-attestation-verification.v1`, `status`, `binding`, `runtime_validation`, `errors`, and `limitations`; compare signatures with `hmac.compare_digest` and reject booleans wherever an integer is required.

- [ ] **Step 4: Bind the existing runtime validator to attested identity**

Add optional keyword-only fields without weakening current callers:

```python
def validate_runtime_proof(
    proof: dict[str, Any], *, policy: LabPolicy | None = None,
    max_events: int = 100_000, expected_run_id: str | None = None,
    expected_target_sha256: str | None = None,
) -> dict[str, Any]:
```

Append `run_id_mismatch` and `target_sha256_mismatch` to gate errors when expected values are supplied and differ. Extend existing tests to prove omitted expectations preserve current behavior and malformed expectations return `invalid` rather than raising.

- [ ] **Step 5: Run GREEN and regression tests**

Run: `python -m pytest tests/test_vm_attestation.py tests/test_lab_policy.py -q`

Expected: all tests pass; no test executes a target or VM.

- [ ] **Step 6: Commit the independently testable contract**

```bash
git add aether_re/vm_attestation.py aether_re/lab_policy.py tests/test_vm_attestation.py tests/test_lab_policy.py
git commit -m "feat: bind dynamic lab proofs to signed run leases"
```

---

### Task 2: Provider-Neutral Fail-Closed VM Lifecycle

**Files:**
- Create: `aether_re/vm_lab.py`
- Create: `tests/test_vm_lab.py`
- Modify: `aether_re/dynamic_effects.py:17-101`

**Interfaces:**
- Consumes: Task 1 `issue_run_lease` and `verify_attestation`; existing `LabPolicy`; existing `validate_effects(events: Any, *, allowed_write_roots: list[Path] | None = None, allow_network: bool = False, max_events: int = 100_000) -> dict[str, Any]`.
- Produces: immutable `VMRunRequest`; `VMProvider` protocol methods `probe`, `prepare`, `execute`, `collect`, `rollback`, `verify_rollback`, `cleanup`; `run_dynamic_case(request: VMRunRequest, *, provider: VMProvider, attestation_key: bytes, clock: Callable[[], datetime]) -> dict[str, Any]`.

- [ ] **Step 1: Write lifecycle order and failure-precedence tests**

```python
def test_dynamic_case_verifies_rollback_after_success(tmp_path):
    provider = RecordingProvider(valid_attestation=True)
    report = run_dynamic_case(_request(tmp_path), provider=provider,
                              attestation_key=KEY, clock=fixed_clock)
    assert provider.calls == ["probe", "prepare", "execute", "collect",
                              "rollback", "verify_rollback", "cleanup"]
    assert report["status"] == "verified"
    assert report["target_executed_on_host"] is False

@pytest.mark.parametrize("failure", ["prepare", "execute", "collect", "rollback", "verify_rollback"])
def test_dynamic_case_never_verifies_when_any_lifecycle_stage_fails(tmp_path, failure):
    provider = RecordingProvider(fail_at=failure)
    report = run_dynamic_case(_request(tmp_path), provider=provider,
                              attestation_key=KEY, clock=fixed_clock)
    assert report["status"] != "verified"
    assert provider.calls[-1] == "cleanup"

def test_cancel_timeout_and_keyboard_interrupt_still_attempt_rollback(tmp_path):
    for failure in (TimeoutError("expired"), KeyboardInterrupt()):
        provider = RecordingProvider(execute_error=failure)
        report = run_dynamic_case(_request(tmp_path), provider=provider,
                                  attestation_key=KEY, clock=fixed_clock)
        assert "rollback" in provider.calls and provider.calls[-1] == "cleanup"
        assert report["status"] in {"cancelled", "failed"}
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/test_vm_lab.py -q`

Expected: collection fails because `aether_re.vm_lab` does not exist.

- [ ] **Step 3: Implement explicit lifecycle contracts**

```python
@dataclass(frozen=True)
class VMRunRequest:
    run_id: str
    vm_name: str
    snapshot_id: str
    target_path: Path
    target_sha256: str
    authorization_path: Path
    authorization_sha256: str
    collector_sha256: str
    timeout_s: int
    memory_limit_mb: int
    max_events: int = 100_000

class VMProvider(Protocol):
    def probe(self, request: VMRunRequest) -> dict[str, Any]: raise NotImplementedError
    def prepare(self, request: VMRunRequest, lease: dict[str, Any]) -> dict[str, Any]: raise NotImplementedError
    def execute(self, request: VMRunRequest, lease: dict[str, Any]) -> dict[str, Any]: raise NotImplementedError
    def collect(self, request: VMRunRequest, execution: dict[str, Any]) -> dict[str, Any]: raise NotImplementedError
    def rollback(self, request: VMRunRequest) -> dict[str, Any]: raise NotImplementedError
    def verify_rollback(self, request: VMRunRequest) -> dict[str, Any]: raise NotImplementedError
    def cleanup(self, request: VMRunRequest) -> dict[str, Any]: raise NotImplementedError
```

Implement `run_dynamic_case` as a state machine. Reject symlink/missing target, bad hashes, absent authorization, non-positive budgets, host/container provider claims, network enabled state, writable mounts, or any unverified lifecycle stage before `execute`. In `finally`, attempt rollback after every successful prepare and always call cleanup. Preserve primary and cleanup errors separately.

- [ ] **Step 4: Validate guest effects before accepting a run**

Pass collected events to `validate_effects`; require its status to be acceptable and its event count to match the signed attestation. Add tests for writes outside declared guest roots, network events while network is denied, and event-count disagreement.

- [ ] **Step 5: Run GREEN and boundary regression**

Run: `python -m pytest tests/test_vm_lab.py tests/test_dynamic_effects.py tests/test_adversarial_boundaries.py -q`

Expected: all pass and the fake provider proves rollback attempts under every injected failure.

- [ ] **Step 6: Commit**

```bash
git add aether_re/vm_lab.py aether_re/dynamic_effects.py tests/test_vm_lab.py tests/test_dynamic_effects.py
git commit -m "feat: add fail-closed disposable VM lifecycle"
```

---

#### Task 2B: Real Hyper-V Worker and Benign Qualification

**Files:**
- Create: `aether_re/vm_hyperv.py`
- Create: `tools/qualify_hyperv_lab.py`
- Create: `tests/fixtures/release/benign_probe.ps1`
- Create: `tests/test_vm_hyperv.py`
- Create: `docs/DYNAMIC_LAB_RUNBOOK.md`
- Modify: `megazord.py:479-510`
- Modify: `megazord.py:786-1077`

**Interfaces:**
- Consumes: Task 2 `VMProvider`, `VMRunRequest`, `run_dynamic_case`; existing `run_bounded` process discipline.
- Produces: `HyperVConfig(vm_name: str, checkpoint_name: str, guest_username_env: str, guest_password_env: str, workspace: str)`; `HyperVProvider(config: HyperVConfig, *, command_runner: CommandRunner)`; CLI `lab-qualify-hyperv`.
- Security boundary: credentials are read from named environment variables at invocation, never serialized; command logs contain redacted argument roles, not passwords.

- [ ] **Step 1: Write exact-command and no-host-execution tests**

```python
def test_hyperv_prepare_restores_checkpoint_disconnects_all_adapters_and_proves_vm(tmp_path):
    runner = ScriptedRunner(successful_hyperv_responses())
    provider = HyperVProvider(_config(), command_runner=runner)
    result = provider.prepare(_request(tmp_path), _lease())
    scripts = "\n".join(call.script for call in runner.calls)
    assert "Restore-VMSnapshot" in scripts
    assert "Disconnect-VMNetworkAdapter" in scripts
    assert "Get-VMIntegrationService" in scripts
    assert result["vm_identity"]["generation"] in (1, 2)
    assert all(str(_request(tmp_path).target_path) not in call.executable_args for call in runner.calls)

def test_hyperv_provider_refuses_missing_checkpoint_or_connected_network(tmp_path):
    for responses in (without_checkpoint(), with_connected_adapter_after_disconnect()):
        provider = HyperVProvider(_config(), command_runner=ScriptedRunner(responses))
        assert provider.prepare(_request(tmp_path), _lease())["status"] == "refused"
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/test_vm_hyperv.py -q`

Expected: import failure for `aether_re.vm_hyperv`.

- [ ] **Step 3: Implement the Hyper-V provider with argument-safe PowerShell**

Use `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <UTF-16LE-base64>` through an injected runner. Scripts must set `$ErrorActionPreference='Stop'`, resolve VM/checkpoint by exact name, require `State`, `Generation`, `VMId`, checkpoint ID, zero connected adapters, heartbeat OK, and PowerShell Direct readiness. Never interpolate user values into script source: supply them as base64 JSON decoded inside PowerShell.

Provider stage requirements:

```text
probe           Hyper-V module present; exact VM exists; provider reports real VM identity
prepare         stop VM; restore exact checkpoint; disconnect every adapter; start VM; heartbeat ready
execute         PowerShell Direct copies owned probe + lease into guest and starts a bounded guest job
collect         PowerShell Direct retrieves attestation/events only after guest job exits or is stopped
rollback        stop VM without save; restore the same checkpoint
verify_rollback checkpoint ID unchanged; VM disk/checkpoint metadata match pre-run digest; adapters disconnected
cleanup         delete transient host output and close PSSession; never delete evidence already committed
```

- [ ] **Step 4: Add the owned benign guest probe and attestation collector**

`benign_probe.ps1` must only create/read/delete a file under the supplied guest workspace and emit deterministic `process_start`, `file_write`, `file_read`, `file_delete`, `process_exit` events. The collector hashes the target before execution, records UTC timestamps/sequence numbers, enforces the lease timeout, signs the attestation using the injected ephemeral key, and exits non-zero on collection or cleanup failure.

- [ ] **Step 5: Add CLI and operational documentation**

CLI contract:

```powershell
python tools/qualify_hyperv_lab.py --vm-name RE-LAB-01 --checkpoint clean-v1 `
  --target tests/fixtures/release/benign_probe.ps1 `
  --authorization evidence/authorizations/benign_probe.json `
  --output output/f08_hyperv_qualification.json
```

Exit `0` only for `status=verified`; exit `2` for unavailable/refused; exit `1` for execution/integrity failure. Document guest provisioning, credentials via environment, zero-network verification, snapshot creation, expected benign effects, emergency stop, evidence collection, and teardown. State explicitly that unit tests do not close F08.

- [ ] **Step 6: Run unit GREEN and then the real qualification gate**

Run: `python -m pytest tests/test_vm_hyperv.py tests/test_vm_lab.py tests/test_lab_policy.py -q`

Expected: all unit tests pass.

Run on the qualified Hyper-V host: the CLI command above.

Expected proof: `output/f08_hyperv_qualification.json` reports `verified`, real VM/checkpoint identifiers, network disconnected, heartbeat present, signed event sequence, rollback verified, and `target_executed_on_host=false`. If Hyper-V, credentials, checkpoint, or privilege is unavailable, preserve `refused` evidence and leave F08 non-passing.

- [ ] **Step 7: Commit**

```bash
git add aether_re/vm_hyperv.py tools/qualify_hyperv_lab.py tests/fixtures/release/benign_probe.ps1 tests/test_vm_hyperv.py docs/DYNAMIC_LAB_RUNBOOK.md megazord.py
git commit -m "feat: qualify real disposable Hyper-V laboratory"
```

---

### Task 3: Authorized Corpus Registry and Sealed Blind Split

**Files:**
- Create: `aether_re/corpus_registry.py`
- Create: `tests/test_corpus_registry.py`
- Modify: `aether_re/corpus.py:42-246`
- Modify: `aether_re/metrics.py:111-275`
- Modify: `tools/split_contract.py`

**Interfaces:**
- Consumes: existing corpus manifests, `validate_corpus_builds`, `validate_split_integrity`, and `evaluate_blind_holdout`.
- Produces: `register_corpus(manifest: Any, *, root: Path, max_artifacts: int = 100_000) -> dict[str, Any]`; `seal_partitions(registry: dict[str, Any], *, output: Path) -> dict[str, Any]`; `verify_partition_seal(seal: Any, *, root: Path) -> dict[str, Any]`.
- Artifact identity: SHA-256 of bytes; family identity: explicit stable family ID plus sorted source/build lineage hashes; aliases never create new samples.

- [ ] **Step 1: Write authorization and leakage RED tests**

```python
def test_registry_accepts_only_hash_bound_authorization_and_oracle(tmp_path):
    fixture = materialize_authorized_fixture(tmp_path, count=10)
    report = register_corpus(fixture.manifest, root=tmp_path)
    assert report["status"] == "verified"
    assert report["summary"]["authorized_projects"] >= 10
    assert report["summary"]["oracles"] >= 10

def test_seal_rejects_renamed_duplicate_and_related_family_cross_split(tmp_path):
    fixture = materialize_leaking_fixture(tmp_path)
    report = register_corpus(fixture.manifest, root=tmp_path)
    codes = {item["code"] for item in report["errors"]}
    assert "artifact_identity_cross_split" in codes
    assert "family_lineage_cross_split" in codes

def test_dynamic_permission_is_distinct_from_static_and_build_permission(tmp_path):
    fixture = materialize_authorized_fixture(tmp_path, scopes=["static", "build"])
    report = register_corpus(fixture.manifest, root=tmp_path)
    assert report["artifacts"][0]["permissions"]["dynamic"] is False
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/test_corpus_registry.py -q`

Expected: import failure for `aether_re.corpus_registry`.

- [ ] **Step 3: Implement strict corpus registration**

Require each project to declare `project_id`, `family_id`, `split`, `artifact_path`, `artifact_sha256`, `license`, `authorization_path`, `authorization_sha256`, `permissions`, `oracle_path`, `oracle_sha256`, `source_lineage`, and `build_lineage`. Paths must be relative regular files below `root`, with no symlink component. Allowed splits are exactly `development`, `calibration`, `blind_holdout`, `adversarial`, and `authorized_real`; permissions are explicit booleans for `static`, `build`, and `dynamic`.

Return schema `authorized-corpus-registry.v1`, normalized rows, counts by format/architecture/protection/split, and every error. A single authorization, hash, lineage, oracle, or split error sets `status=invalid`.

- [ ] **Step 4: Implement deterministic partition sealing**

```python
def seal_partitions(registry: dict[str, Any], *, output: Path) -> dict[str, Any]:
    if registry.get("status") != "verified":
        raise ValueError("registry_must_be_verified")
    rows = sorted(registry["artifacts"], key=lambda row: (row["project_id"], row["artifact_sha256"]))
    splits: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        splits.setdefault(row["split"], []).append(row)
    split_digests = {name: hashlib.sha256(_canonical_bytes(items)).hexdigest()
                     for name, items in sorted(splits.items())}
    seal = {"schema": "corpus-partition-seal.v1", "registry_sha256":
            hashlib.sha256(_canonical_bytes(rows)).hexdigest(), "splits": split_digests,
            "artifacts": rows}
    _atomic_write_json_without_overwriting_different(output, seal)
    return seal
```

Replace the ellipsis with canonical row hashing and `os.replace` from a same-directory temporary file. `verify_partition_seal` rehashes every referenced artifact, authorization, and oracle and reports all mismatches.

- [ ] **Step 5: Tighten blind evaluation against the sealed registry**

Extend `evaluate_blind_holdout` with optional `partition_seal: dict[str, Any] | None = None`. When supplied, require every row's `sample_id`, `evidence_id`, `family`, and `artifact_sha256` to match one sealed entry and reject calibration/holdout aliases, family/build lineage overlap, unknown producers, or undeclared abstentions.

- [ ] **Step 6: Run GREEN and all corpus/split regressions**

Run: `python -m pytest tests/test_corpus_registry.py tests/test_corpus.py tests/test_corpus_build.py tests/test_metrics.py tests/test_split_contract.py tests/test_tri_split_ci.py tests/test_tri_split_evaluate.py tests/test_tri_split_release.py tests/test_tri_split_unblind.py -q`

Expected: all pass; the existing public corpus with static-only authorization remains excluded from dynamic evidence.

- [ ] **Step 7: Commit**

```bash
git add aether_re/corpus_registry.py aether_re/corpus.py aether_re/metrics.py tools/split_contract.py tests/test_corpus_registry.py tests/test_metrics.py
git commit -m "feat: seal authorized family-disjoint corpus partitions"
```

---

### Task 4: Stratified Metrics, Calibration, and Baseline Promotion Rules

**Files:**
- Create: `aether_re/certification_metrics.py`
- Create: `tests/test_certification_metrics.py`
- Modify: `aether_re/metrics.py:30-280`
- Modify: `tools/f10_holdout_confidence.py`
- Modify: `tools/f10_scope_metrics_v170.py`

**Interfaces:**
- Consumes: Task 3 verified partition seal; existing `calibration_metrics` and `evaluate_blind_holdout`.
- Produces: `certify_metrics(rows: list[dict[str, Any]], *, partition_seal: dict[str, Any], baseline: dict[str, Any], thresholds: dict[str, float], bootstrap_seed: int = 2077, bootstrap_iterations: int = 2_000) -> dict[str, Any]`; `compare_baseline(candidate: dict[str, Any], baseline: dict[str, Any], *, critical_metrics: tuple[str, ...]) -> dict[str, Any]`.

- [ ] **Step 1: Write RED tests for denominators, abstention, uncertainty, and regression**

```python
def test_certification_keeps_abstentions_and_empty_strata_in_denominators():
    report = certify_metrics(rows_with_abstention_and_empty_architecture(),
                             partition_seal=seal(), baseline=baseline(), thresholds=thresholds())
    assert report["summary"]["received"] == 12
    assert report["summary"]["abstained"] == 2
    assert report["strata"]["architecture:arm64"]["status"] == "insufficient_data"

def test_certification_reports_brier_ece_wilson_and_seeded_bootstrap():
    first = certify_metrics(valid_rows(), partition_seal=seal(), baseline=baseline(),
                            thresholds=thresholds(), bootstrap_seed=2077, bootstrap_iterations=500)
    second = certify_metrics(valid_rows(), partition_seal=seal(), baseline=baseline(),
                             thresholds=thresholds(), bootstrap_seed=2077, bootstrap_iterations=500)
    assert first == second
    assert {"brier", "ece", "precision", "recall", "f1", "abstention_rate"} <= first["metrics"]
    assert "interval_95" in first["metrics"]["precision"]

def test_any_critical_lower_bound_regression_blocks_promotion():
    report = compare_baseline(candidate_with_precision_drop(), baseline(),
                              critical_metrics=("precision", "recall", "brier", "ece"))
    assert report["promotion_allowed"] is False
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/test_certification_metrics.py -q`

Expected: import failure for `aether_re.certification_metrics`.

- [ ] **Step 3: Implement reproducible certification metrics**

Compute exact confusion counts, precision/recall/F1, Brier score, ECE with declared bins, correct/incorrect abstention, coverage, false positives/negatives, timeout rate, resource percentiles, and Wilson 95% intervals for binomial metrics. Produce strata for `format`, `architecture`, `protection`, `profile`, `backend`, and `epistemic_state`, including declared zero-observation strata as `insufficient_data`.

Use a local `random.Random(bootstrap_seed)` for percentile bootstrap intervals and reject boolean/NaN/infinite scores, invalid iteration counts, unknown sealed identities, or any split leakage.

- [ ] **Step 4: Implement fail-closed baseline comparison**

Promotion requires every declared threshold and sufficiency rule to pass and no critical metric to regress outside its allowed delta. For higher-is-better metrics compare candidate lower bound to the baseline floor; for `brier`, `ece`, timeout, false-positive, and incorrect-abstention rates compare candidate upper bound to the baseline ceiling. Missing metrics block promotion.

- [ ] **Step 5: Run GREEN and legacy metrics tests**

Run: `python -m pytest tests/test_certification_metrics.py tests/test_metrics.py tests/test_independent_holdout.py tests/test_tri_split_evaluate.py -q`

Expected: all pass with deterministic JSON for the same seed and inputs.

- [ ] **Step 6: Commit**

```bash
git add aether_re/certification_metrics.py aether_re/metrics.py tools/f10_holdout_confidence.py tools/f10_scope_metrics_v170.py tests/test_certification_metrics.py tests/test_metrics.py
git commit -m "feat: enforce calibrated blind promotion metrics"
```

---

### Task 5: Deterministic Chaos and Red-Team Validation Campaign

**Files:**
- Create: `aether_re/validation_campaign.py`
- Create: `tools/run_validation_campaign.py`
- Create: `tests/test_validation_campaign.py`
- Modify: `tools/f02_fault_campaign.py`
- Modify: `tools/f11_adversarial_campaign.py`
- Modify: `tools/f11_adversarial_cli_campaign.py`

**Interfaces:**
- Consumes: existing custody/checkpoint/repro/phase-gate validators and bounded CLI runners.
- Produces: `CampaignCase(case_id: str, category: str, command: tuple[str, ...], expected_exit: int, expected_codes: tuple[str, ...], timeout_s: int)`; `run_validation_campaign(cases: Sequence[CampaignCase], *, root: Path, output: Path, max_cases: int = 500) -> dict[str, Any]`.

- [ ] **Step 1: Write RED tests for all mandatory attack classes**

```python
def test_campaign_covers_mandatory_chaos_and_red_team_classes(tmp_path):
    report = run_validation_campaign(mandatory_cases(), root=tmp_path,
                                     output=tmp_path / "campaign.json")
    assert set(report["summary"]["categories"]) >= {
        "journal_truncation", "commit_crash", "concurrency", "disk_full",
        "timeout", "cancellation", "parser_bomb", "archive_traversal",
        "prompt_injection", "citation_tamper", "oversized_output", "schema_confusion",
    }
    assert report["status"] == "passed"

def test_campaign_does_not_accept_unexpected_success_or_missing_error_code(tmp_path):
    report = run_validation_campaign([case_returning_wrong_result()], root=tmp_path,
                                     output=tmp_path / "campaign.json")
    assert report["status"] == "failed"
    assert report["summary"]["failed"] == 1
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/test_validation_campaign.py -q`

Expected: import failure for `aether_re.validation_campaign`.

- [ ] **Step 3: Implement bounded campaign execution and evidence capture**

Validate unique case IDs, allowed categories, tuple commands with no shell, timeouts `1..3600`, max cases `1..500`, root confinement, and expected machine-readable error codes. Capture exit code, duration, stdout/stderr SHA-256, redacted tails, and produced evidence hashes. Kill the complete process tree on timeout and record `timeout` rather than treating it as a generic failure.

- [ ] **Step 4: Materialize the mandatory case matrix**

Bind existing F02 scripts for journal truncation, commit crash, multiprocessing/concurrency, logical and physical ENOSPC, cancellation, recovery, and tamper. Bind F11 cases for scalar/malformed JSON, duplicate keys/paths, symlink/path traversal, archive expansion, gigantic events, Unicode/control characters, prompt-injection strings treated as data, citation/evidence hash tampering, and CLI encoding. Each case must name exact expected codes and artifacts.

- [ ] **Step 5: Run GREEN and the complete offline campaign**

Run: `python -m pytest tests/test_validation_campaign.py tests/test_checkpoint.py tests/test_custody.py tests/test_repro_package.py tests/test_review_ui.py tests/test_adversarial_boundaries.py -q`

Then run: `python tools/run_validation_campaign.py --root . --output output/f02_f11_validation_campaign.json`

Expected: unit suite passes; campaign JSON is `passed` only if every mandatory case executed and matched its expected outcome. Physical disk-full cases that cannot be exercised leave the campaign `partial`, not `passed`.

- [ ] **Step 6: Commit**

```bash
git add aether_re/validation_campaign.py tools/run_validation_campaign.py tools/f02_fault_campaign.py tools/f11_adversarial_campaign.py tools/f11_adversarial_cli_campaign.py tests/test_validation_campaign.py
git commit -m "test: unify chaos and adversarial release campaigns"
```

---

### Task 6: Clean Install, Deterministic Replay, and Evidence Hash Comparison

**Files:**
- Create: `aether_re/release_replay.py`
- Create: `tools/run_release_replay.py`
- Create: `tests/test_release_replay.py`
- Modify: `aether_re/repro_package.py:69-281`
- Modify: `tools/f00_clean_replay_v2.py`
- Modify: `tools/run_full_clean_suite_v165.py`

**Interfaces:**
- Consumes: existing `create_repro_package`, `verify_repro_package`, `restore_repro_package`, and homologation.
- Produces: `build_replay_recipe(*, source_commit: str, python_version: str, lock_sha256: str, commands: list[list[str]], expected_artifacts: list[dict[str, str]]) -> dict[str, Any]`; `execute_clean_replay(recipe: Any, *, source_archive: Path, workspace: Path, wheelhouse: Path, output: Path, max_seconds: int = 14_400) -> dict[str, Any]`.

- [ ] **Step 1: Write RED tests for deterministic recipe and tamper rejection**

```python
def test_clean_replay_uses_locked_offline_inputs_and_matches_expected_hashes(tmp_path):
    runner = FakeReplayRunner(reproduced={"gate.json": "a" * 64})
    report = execute_clean_replay(recipe(expected={"gate.json": "a" * 64}),
                                  source_archive=source_archive(tmp_path), workspace=tmp_path / "fresh",
                                  wheelhouse=wheelhouse(tmp_path), output=tmp_path / "replay.json",
                                  runner=runner)
    assert report["status"] == "verified"
    assert runner.network_enabled is False

def test_clean_replay_rejects_lock_source_member_and_result_tamper(tmp_path):
    for mutated in (bad_lock_recipe(), bad_source_recipe(), traversal_archive(), wrong_result_recipe()):
        report = execute_clean_replay(mutated, source_archive=source_archive(tmp_path),
                                      workspace=tmp_path / unique_name(), wheelhouse=wheelhouse(tmp_path),
                                      output=tmp_path / unique_report(), runner=FakeReplayRunner())
        assert report["status"] in {"invalid", "failed"}
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/test_release_replay.py -q`

Expected: import failure for `aether_re.release_replay`.

- [ ] **Step 3: Implement recipe validation and atomic fresh-workspace replay**

Add an injected `runner` keyword-only dependency to the exact production signature for unit tests. Require an absent destination, regular source/wheelhouse inputs, locked hashes, no absolute/traversal/symlink archive members, commands as non-empty string lists, no shell metacharacter interpretation, bounded output, and network-disabled environment. Create the venv inside the fresh workspace, install only from the hash-verified wheelhouse, run declared commands, and hash expected artifacts.

- [ ] **Step 4: Extend repro packages with replay recipe binding**

Require release repro packages to contain `replay_recipe.json`, its digest in the manifest, the dependency lock digest, source archive digest, environment fingerprint, and expected result hashes. Existing non-release packages remain valid under their prior schema; release certification requires the new schema.

- [ ] **Step 5: Run GREEN, clean replay, and hash comparison**

Run: `python -m pytest tests/test_release_replay.py tests/test_repro_package.py tests/test_homologation.py -q`

Then run in a newly created workspace: `python tools/run_release_replay.py --recipe evidence/release/replay_recipe.json --source evidence/release/source.zip --wheelhouse evidence/release/wheelhouse --workspace D:\RE_Megazord_Replay_Clean --output output/f12_clean_replay.json`

Expected: `verified` only if installation, full suite, campaign, and every expected artifact hash match; otherwise retain exact mismatches and keep F12 non-passing.

- [ ] **Step 6: Commit**

```bash
git add aether_re/release_replay.py aether_re/repro_package.py tools/run_release_replay.py tools/f00_clean_replay_v2.py tools/run_full_clean_suite_v165.py tests/test_release_replay.py tests/test_repro_package.py
git commit -m "feat: add offline clean-install release replay"
```

---

### Task 7: Independent Review Attestation and F00-F12 Release Certification

**Files:**
- Create: `aether_re/release_certification.py`
- Create: `tools/certify_release.py`
- Create: `tests/test_release_certification.py`
- Create: `docs/RELEASE_CERTIFICATION.md`
- Modify: `aether_re/phase_gates.py:113-314`
- Modify: `aether_re/homologation.py:42-155`
- Modify: `megazord.py:697-711`
- Modify: `megazord.py:786-1077`

**Interfaces:**
- Consumes: Task 2B VM qualification, Task 3 seal, Task 4 metric certificate, Task 5 campaign, Task 6 clean replay, existing `evaluate_phase_gates` and `audit_run_package`.
- Produces: `verify_independent_review(review: Any, *, release_sha256: str, trusted_reviewers: dict[str, bytes], now: datetime) -> dict[str, Any]`; `certify_release(manifest: Any, *, root: Path, trusted_reviewers: dict[str, bytes], now: datetime) -> dict[str, Any]`.
- Independence rule: author identity, implementer identities, and reviewer identity are non-empty and pairwise disjoint; reviewer key ID must exist in the external trust map, never inside the package being reviewed.

- [ ] **Step 1: Write RED tests for independent review and aggregate gate truth**

```python
def test_release_passes_only_with_all_thirteen_gates_and_independent_signature(tmp_path):
    package = materialize_complete_release(tmp_path)
    report = certify_release(package.manifest, root=tmp_path,
                             trusted_reviewers={"reviewer-b": REVIEWER_KEY}, now=FIXED_NOW)
    assert report["status"] == "complete"
    assert report["gate_passed"] is True
    assert [row["gate_id"] for row in report["gates"]] == [f"F{i:02d}" for i in range(13)]

@pytest.mark.parametrize("mutation", [
    "missing_gate", "partial_gate", "tampered_evidence", "active_lock", "vm_declaration_only",
    "holdout_leakage", "metric_regression", "campaign_partial", "replay_mismatch",
    "self_review", "unknown_reviewer", "expired_review", "review_signature_tamper",
])
def test_release_fails_closed_for_every_mandatory_boundary(tmp_path, mutation):
    package = materialize_release_with_mutation(tmp_path, mutation)
    report = certify_release(package.manifest, root=tmp_path,
                             trusted_reviewers={"reviewer-b": REVIEWER_KEY}, now=FIXED_NOW)
    assert report["status"] == "partial"
    assert report["gate_passed"] is False
```

- [ ] **Step 2: Run RED**

Run: `python -m pytest tests/test_release_certification.py -q`

Expected: import failure for `aether_re.release_certification`.

- [ ] **Step 3: Implement signed independent-review verification**

Review schema `independent-review.v1` contains `review_id`, `reviewer_id`, `reviewer_key_id`, `author_id`, `implementer_ids`, `release_sha256`, `reviewed_at`, `expires_at`, `verdict`, `reexecuted_commands`, `observed_artifacts`, `disputes`, and `signature`. Verify HMAC using the external trusted key map, UTC validity, exact release digest, identity separation, non-empty reexecution, every observed artifact hash, and `verdict=approved`. Any dispute with status other than `resolved` blocks approval.

- [ ] **Step 4: Implement the evidence-to-gate matrix**

The release manifest must bind the following evidence, and certification must invoke each artifact's native validator rather than trusting its declared status:

| Gate | Native proof consumed by certification |
|---|---|
| F00 | frozen baseline, inventory, source commit, dependency lock, full-suite JUnit |
| F01 | authorization registry, threat model, license/SBOM audit |
| F02 | custody/journal/recovery plus complete chaos campaign |
| F03 | verified registry with 10+ authorized complex projects and independent oracles |
| F04 | measured language-profile/semantic reports |
| F05 | build/oracle provenance and no authorization-scope extrapolation |
| F06 | holdout graph/entity/relation precision-recall certificate |
| F07 | PE/ELF multiarch and source-build-binary differential reports |
| F08 | Task 2B real-VM qualification with signed lease, rollback, network isolation, heartbeat |
| F09 | bounded useful fuzz/symbolic/dynamic reports bound to F08 where execution occurred |
| F10 | Task 4 sealed blind metric certificate with no critical regression |
| F11 | Task 5 complete adversarial campaign and safe offline review rendering |
| F12 | Task 6 clean replay, homologation, campaign, and Task 7 independent review |

Build the document passed to `evaluate_phase_gates` from computed validator results. Never copy `implementation`, `integration`, `reviewed`, test counts, or status from an unverified source. `reviewed=True` is derived only from `verify_independent_review(status=verified)`.

- [ ] **Step 5: Extend phase-gate output with exact debt while preserving schema compatibility**

Add `blocking_gates`, `integrity_errors`, and `debt` arrays to the report. Preserve current phase rows and `gate_passed` semantics. Map missing/non-passing required validators to `NAO_COMPROVADA`, explicit failed campaigns/tests to `NAO_QUITADA`, and real but incomplete proof to `PARCIALMENTE_QUITADA`.

- [ ] **Step 6: Add final CLI and independent-review runbook**

```powershell
python tools/certify_release.py --manifest evidence/release/release_manifest.json `
  --root . --trusted-reviewers C:\Secure\re_megazord_reviewers.json `
  --output output/final_release_certificate.json
```

Exit `0` only for `complete`; exit `3` for `partial`; exit `1` for malformed/unreadable input. Document how the reviewer receives a sealed package, works in a fresh environment, verifies hashes before execution, replays commands, records disagreements, signs outside the project tree, and returns only the attestation.

- [ ] **Step 7: Run GREEN and all gate/homologation regressions**

Run: `python -m pytest tests/test_release_certification.py tests/test_phase_gates.py tests/test_homologation.py tests/test_claims.py tests/test_blind_release.py tests/test_independent_holdout.py -q`

Expected: all pass; self-review and declaration-only VM evidence remain non-passing.

- [ ] **Step 8: Commit**

```bash
git add aether_re/release_certification.py aether_re/phase_gates.py aether_re/homologation.py tools/certify_release.py tests/test_release_certification.py docs/RELEASE_CERTIFICATION.md megazord.py
git commit -m "feat: certify releases from independently verified F00-F12 evidence"
```

---

#### Task 7B: Full Campaign, Fresh Replay, and External Review Handoff

**Files:**
- Modify: `README.md`
- Modify: `docs/EXTERNAL_EVIDENCE_HANDOFF.md`
- Create at execution time: `evidence/release/release_manifest.json`
- Create at execution time: `evidence/release/replay_recipe.json`
- Create at execution time: `output/final_full_suite.junit.xml`
- Create at execution time: `output/f02_f11_validation_campaign.json`
- Create at execution time: `output/f08_hyperv_qualification.json`
- Create at execution time: `output/f10_blind_metric_certificate.json`
- Create at execution time: `output/f12_clean_replay.json`
- Create at execution time: `output/final_release_certificate.json`

**Interfaces:**
- Consumes: all prior task CLIs and validators.
- Produces: one sealed external-review package and, after a distinct reviewer returns a valid attestation, one final certificate whose `gate_passed` value is the sole release-completion signal.

- [ ] **Step 1: Run the complete repository suite before generating evidence**

Run: `python -m pytest -q --junitxml=output/final_full_suite.junit.xml`

Expected: zero failed/error tests. A skipped mandatory real-VM, physical disk-full, blind-holdout, or replay test blocks the corresponding gate even if pytest exits zero.

- [ ] **Step 2: Run the real-VM qualification and bounded F09 jobs**

Run the Task 2B qualification command, then run the repository's bounded fuzz, symbolic, and benign trace commands only against artifacts whose authorization includes `dynamic=true`. Require all execution evidence to reference the same verified F08 provider/checkpoint generation and a unique signed lease.

Expected: F08 stays non-passing unless rollback and isolation are materially verified; F09 stays non-passing if jobs are merely static contracts or provide no measured utility.

- [ ] **Step 3: Run sealed blind evaluation exactly once after calibration freeze**

Freeze calibration configuration and digest, verify the Task 3 partition seal, execute predictions without exposing holdout oracles to the prediction process, then call Task 4 certification.

Expected: `output/f10_blind_metric_certificate.json` records denominators, intervals, strata, abstentions, threshold decisions, baseline deltas, and the seal digest. Any family/identity/evidence overlap invalidates the run and requires a new blind set.

- [ ] **Step 4: Run chaos and red-team campaigns**

Run: `python tools/run_validation_campaign.py --root . --output output/f02_f11_validation_campaign.json`

Expected: all mandatory cases pass with exact expected codes; partial physical tests keep F02/F11 partial and are not waived by the release tool.

- [ ] **Step 5: Build and execute the clean replay outside the working tree**

Generate the locked source archive, offline wheelhouse, recipe, and expected hashes. Run Task 6 in a new directory with no inherited virtual environment and network disabled.

Expected: `output/f12_clean_replay.json` is `verified` and reproduces the declared suite/campaign/evidence hashes. Mismatch requires investigation and a new release candidate digest.

- [ ] **Step 6: Generate the unsigned candidate certificate and handoff package**

Run Task 7 without a review attestation.

Expected: certificate is intentionally `partial` with only `independent_review_missing` blocking F12 after every other proof passes. Package the candidate manifest, replay recipe, source, wheelhouse, SBOM/licenses, threat model, corpus seal without hidden oracles, VM proof, campaign, metrics, JUnit, and hash manifest.

- [ ] **Step 7: Obtain independent reexecution and attestation**

A reviewer not listed as author or implementer follows `docs/RELEASE_CERTIFICATION.md` on a separate fresh workspace, verifies the package, reruns the declared commands, records every deviation/dispute, and signs the exact candidate release SHA-256 with a key already present in the external trust map.

Expected: a review containing self-approval, unknown key, unverified command, unresolved dispute, different release digest, or expired timestamp is rejected.

- [ ] **Step 8: Issue the final certificate and verify it twice**

Run the Task 7 CLI with the returned review, then independently rerun it in the clean replay workspace.

Expected: both byte-identical reports have `schema=release-certification.v1`, `status=complete`, `gate_passed=true`, 13 `QUITADA` rows, zero integrity errors, zero blocking gates, and the same evidence root hash. Otherwise publish the exact debt and do not claim completion.

- [ ] **Step 9: Update public documentation with measured scope only**

README and handoff documentation must list tested profiles/formats/architectures, corpus denominators, metric intervals, abstention, resource bounds, VM provider/checkpoint proof, limitations, and exact replay command. Do not use universal/exact-source language beyond certified profiles and epistemic state.

- [ ] **Step 10: Commit documentation and immutable manifest references only**

```bash
git add README.md docs/EXTERNAL_EVIDENCE_HANDOFF.md evidence/release/release_manifest.json evidence/release/replay_recipe.json
git commit -m "release: publish independently verified F00-F12 evidence manifest"
```

Do not commit secrets, reviewer keys, guest credentials, raw private corpus, hidden holdout oracles, volatile VM disks, or unredacted logs.

## Completion Audit

Before execution is called complete, the implementing team must run these checks in order:

1. Every path in the locked file structure exists and has one responsibility.
2. Every public signature in the Interfaces blocks matches its callers and tests exactly.
3. Every task demonstrates RED before implementation and GREEN afterward.
4. The complete suite has zero failures/errors and no skipped mandatory gate exercise.
5. F08 evidence comes from a real VM and proves network isolation plus rollback; a mock, WSL, container, or policy declaration is insufficient.
6. Corpus contains at least ten complex authorized projects with independent oracles and a sealed family-disjoint holdout.
7. Metrics include denominators, 95% intervals, calibration, correct/incorrect abstention, strata, and baseline deltas.
8. Chaos includes crash, truncation, concurrency, cancellation, timeout, OOM/resource limits, and real disk-full evidence; red team includes parser/archive/prompt/citation attacks.
9. Clean installation replays offline in a fresh directory and reproduces expected evidence hashes.
10. Independent reviewer identity is disjoint from author/implementers and its signature validates through an external trust map.
11. `certify_release` verifies native artifacts rather than trusting their status strings.
12. Both original and clean environments produce the same final certificate with all 13 gates `QUITADA` and zero integrity errors.

If any check fails, the deliverable remains `PARCIALMENTE_QUITADA`, `NAO_QUITADA`, or `NAO_COMPROVADA` according to the evidence. There is no percentage-based override.
