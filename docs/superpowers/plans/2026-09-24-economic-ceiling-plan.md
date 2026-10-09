# RE_Megazord Economic Maximum-Ceiling Execution Plan

> **For agentic workers:** execute task-by-task with `superpowers:executing-plans`; do not restart completed work or fan out agents unless a later explicit request authorizes it. Steps use checkboxes for tracking.

**Goal:** Raise RE_Megazord to the strongest evidence-backed forensic extraction and behavior-reconstruction system practical on this host, with certified support stated per format/profile rather than as an untestable universal claim.

**Architecture:** Preserve the existing Evidence Kernel, adapters, corpus, static analyzers, reconstruction engine, and differential comparator. Close one end-to-end vertical slice first: authorized input → extraction → evidence-bound candidate reconstruction → isolated execution → captured observations → differential result → reproducible release evidence. Expand format coverage only after that slice passes.

**Tech Stack:** Existing Python 3.13 CLI, pytest wrapper, Ghidra/Rizin/angr/Capstone/Unicorn adapters, current corpus and holdout, Windows Sandbox/Hyper-V, JSON v1 evidence contracts.

**Spec:** `docs/superpowers/specs/2026-09-22-universal-forensic-reconstruction-design.md` and `docs/PLANO_MESTRE_ENGENHARIA_FORENSE_2026-09-15.md`.

## Global Constraints

- A gate is `QUITADA` only with current, hash-bound evidence and passing acceptance tests.
- Keep every existing change; do not reset, clean, stash, or delete the preserved working tree.
- Rotor-LLM is outside this project's scope; preserve `corpus/authorized_local_rotor_v1` but do not use its files as targets, dependencies, oracles, or evaluation samples.
- Certify each format/architecture/profile separately; one passing profile never means universal support.
- Never execute an unknown target on the host; dynamic runs require a qualified disposable guest, scope, budgets, and rollback evidence.
- Distinguish original source, decompiler output, pseudo-source, generated candidate, and behaviorally tested candidate.
- A 100% claim is allowed only for a finite, named domain whose complete oracle set was tested; never claim it for arbitrary software or all future inputs.
- Reuse installed tools and authorized corpus first. Download or add dependencies only to close a demonstrated profile gap.
- Save full logs and machine reports to disk; show only verdict, denominator, failures, and artifact links in chat.
- Run focused tests per change; run the full suite at integration and release gates. Do not repeat unchanged campaigns.

## Review Focus

- Stripped or optimized binaries with missing source/debug data: report irrecoverable information as unknown, not reconstructed fact.
- Inputs that the tool cannot execute in a guest: return typed blocked/partial results, never simulated success.
- Original/candidate observations with missing, duplicate, or mismatched inputs: reject comparison as invalid.
- Stale, unbound, or tampered evidence: reject it before any gate promotion.
- Unsupported format or architecture: identify the boundary and preserve the raw artifact/hash without silently routing to a wrong parser.

---

## Baseline ruling (verified 2026-09-24)

- `megazord status` exits 0; Ghidra, Rizin, angr, and Unicorn report available; Frida and Binary Ninja report unavailable.
- `output/f12_universal_release_final.json`: `PARCIALMENTE_QUITADA`, `gate_passed=false`, 13/13 debts, zero evidence sources. This report predates the new Sandbox run and must be regenerated after evidence binding.
- `output/f12_phase_gate_report_v181.json`: all 13 gates are partial; last updated 2026-09-22.
- New benign Sandbox evidence is at `E:/AetherRE_Evidence/f08-sandbox-clean-shutdown-retry-20260924-084417/report.json`; it proves guest launch/result return and unchanged host sentinel. It does not prove target execution, trace collection, containment under adversarial behavior, or rollback.
- Existing `reconstruct.run_reconstruct` emits function sketches and pseudo-source, with confidence capped at 0.85. `compare_observations` compares supplied observations; it does not run either program.
- Holdout artifacts cover four small C/x86-64 projects; current measured candidate-symbol precision is about 9–13%, and the targets were not executed. The clean source candidate v4 replay passed 508/508 tests in 153.576 seconds, with zero failures/errors/skips; two-fresh-environment offline replay remains unproved.
- Full `git status --short --untracked-files=all` currently enumerates 498 entries (17 modified, 481 untracked); the live raw status and all-path classification are bound in `E:/AetherRE_Evidence/re-megazord-f00-custody-20260924-091323/working-tree-classification-v4-20260924.json`. Fifty-five `corpus/authorized_local_rotor_v1/` paths are preserved and explicitly out of scope.
- The first external custody snapshot is `E:/AetherRE_Evidence/re-megazord-f00-custody-20260924-091323/custody-snapshot.v1.json`: 5,567 eligible file hashes, 847 excluded entries, HEAD `38a14f4f28661f3f812d2661c929c54c8b826ea2`, inventory SHA-256 `625d7af119ec40441934ecbedfa4d39cead34cd2694775c57281cb81b6d2a5b8`. The capture intentionally prunes `corpus/` and `output/`; their registered manifests require separate verification.
- A path-based classification of all 497 Git entries is saved at `E:/AetherRE_Evidence/re-megazord-f00-custody-20260924-091323/working-tree-classification.v1.json` with the raw status at `git-status-all-20260924.txt`. Counts: 62 implementation, 77 tests, 7 documentation/plans, 4 tools, 9 config/restore, 279 corpus awaiting provenance review, 55 out-of-scope Rotor paths, and 4 generated binaries. This is preliminary path classification, not semantic approval.
- The historical `output/f00_program_baseline.json` lists 1,717 included inventory entries, including 1,384 under corpus; Rotor paths are expressly listed in its excluded scope, not in the included inventory. It is a prior baseline, not proof that current corpus entries are licensed or releasable.

### Task 1 completion evidence (2026-09-24)

- Task 1 is `QUITADA`: the clean source candidate contains 1,782 files (4,829,326 bytes), inventory SHA-256 `a0e1a7cf7ea36ce467f4408355154e3ee0f0f00075ba810945e49847517a23ab`, and zero Rotor paths. Compared with the historical program baseline: 65 added, 22 changed, 0 removed.
- The full suite passed 508 tests with 0 failures, 0 errors, and 0 skips; all 95 `aether_re` modules imported and `compileall` passed. Focused custody/snapshot tests passed 17/17.
- Standard pytest collection is constrained to `tests/` and the incompatible globally installed `nengo` plugin is blocked by `pytest.ini`; this fixes the observed nested-Juliet collection error and the host plugin's incompatible hook.
- Full hash-bound bundle: `E:/AetherRE_Evidence/re-megazord-f00-custody-20260924-091323/f00-task1-final-evidence-v1.json` (SHA-256 `e92c2cb3c91103916d9fe2cb03b771b17fed6976cc32e79de84d9b7540671c0b`). Ghidra and MSVC test inputs were explicit, hash-bound static parser inputs; no target was executed. Toolchain locking and two isolated offline replays remain open in later tasks.

## Execution Strategy

**Fastest credible route:** recover a clean, auditable baseline; bind current evidence; complete one behavioral vertical slice on the smallest authorized deterministic program; then use the same pipeline to expand the supported-profile matrix. Do not spend time increasing the number of parsers, LLM prompts, or benchmark runs before the vertical slice proves it can produce and test a candidate.

**Token control:** one implementation stream, one compact checkpoint after each gate, existing reports reused unless stale or unbound, targeted tests during work, one full regression at the integration boundary and one at release, one independent review on the frozen release candidate.

## File Map

- `aether_re/custody.py`, `tools/custody_snapshot.py`, `.superpowers/sdd/2026-09-22-re-megazord-program/progress.md`: preserve and reconcile current project state.
- `aether_re/dynamic_lab_contracts.py`, `aether_re/lab_policy.py`, `tools/f08_windows_sandbox_probe.py`: bind VM lease, scope, budgets, guest result, rollback/cleanup evidence.
- `aether_re/engines/reconstruct.py`, `aether_re/pipeline.py`, `aether_re/models.py`: define and emit candidate status and evidence references without calling pseudo-source original code.
- `aether_re/differential.py`, `aether_re/dynamic_effects.py`, `megazord.py`: collect/validate runtime observations and expose the bounded comparison workflow.
- `tests/test_dynamic_lab_contracts.py`, `tests/test_lab_policy.py`, `tests/test_differential.py`, new `tests/test_behavioral_runner.py`: pin failure and success behavior.
- `output/`: immutable run-specific reports, hashes, logs, JUnit, corpus metrics, and release manifest; never overwrite a prior evidence run.

## Tasks

### Task 1: Freeze and reconcile custody (F00/F02)

**Acceptance:** no user change is discarded; each path currently reported by Git is classified as implementation, test, documentation, required fixture, generated artifact, or unrelated; a tracked source snapshot and reproducible commands identify exactly what is under release review.

- [x] Preserve the existing tree and current branch/HEAD/status in a new hash-bound custody manifest outside the repository under `E:\AetherRE_Evidence\re-megazord-f00-custody-20260924-091323\`.
- [x] Reconcile the Git status paths against `output/f00_program_baseline.json` and the existing project snapshot; retain source/tests/docs, exclude generated caches from the release package while preserving their hashes where material.
- [x] Mark every `corpus/authorized_local_rotor_v1/` path out of scope for RE_Megazord evaluation, preserving it untouched; verify public Juliet/bootstrap corpus provenance before including it in any denominator.
- [x] Produce a clean replay candidate containing all required implementation files; verify no module/test depends on an untracked file absent from that candidate.
- [x] Run focused custody/snapshot tests (`tests/test_custody.py`, `tests/test_project_snapshot.py`) before changing analyzers.

### Task 2: Reconcile current proof into the gates (F03/F06/F08/F12)

**Acceptance:** every referenced artifact exists, its hash and run date are current, its scope is explicit, and the gate evaluator refuses stale or incomplete proof.

- [ ] Bind the 2026-09-24 Sandbox report and prior capability probe to one F08 evidence record; keep `target_executed=false` and rollback/trace as unproved.
- [ ] Reconcile the holdout build, validation, and binary-evaluation records into one manifest/version, preserving per-sample denominator, compiler, architecture, symbols, relation metrics, and `executed=false`.
- [ ] Rebuild the F00–F12 phase report from the bound evidence and record every debt with its missing artifact/test.
- [ ] Run `tests/test_phase_gates.py`, `tests/test_release_certification.py`, and the affected evidence-contract tests; expect a partial release until later tasks pass.

### Task 3: Complete one bounded executable reconstruction slice (F04/F05/F06)

**Acceptance:** one authorized, deterministic, small C program with source and binary produces an evidence-linked candidate that compiles; the candidate and original run against the same declared cases; every divergence is retained as a counterexample.

- [ ] Reuse the existing smallest C holdout/development sample and current Ghidra/Rizin output; choose one profile with available symbols/debug facts instead of broadening formats.
- [ ] Add a typed candidate status (`candidate`, `pseudo_source_only`, `unsupported`, `partial`) and bind its source/binary/toolchain/input hashes; never label pseudo-source as a working clone.
- [ ] Implement an isolated observation runner that accepts only a validated dynamic-lab lease, executes the original and candidate on identical declared inputs, captures stdout/stderr, exit/exception, bounded filesystem/network effects, timeout, and guest identity, and emits `differential-observation.v1` rows.
- [ ] Add CLI `behavior-compare` that feeds only validated observations to the existing comparator; preserve unknown effects as unknown and fail closed on missing or duplicate input cases.
- [ ] Add `tests/test_behavioral_runner.py` for valid matching behavior, output mismatch, exception mismatch, timeout, guest refusal, tampered target hash, missing observation, and duplicate input.
- [ ] Run focused tests and one benign real-guest vertical slice; publish case denominator, matched count, mismatches, limits, and hashes.

### Task 4: Qualify dynamic isolation and rollback (F08/F09)

**Acceptance:** a real disposable VM/guest is identified; network and resource budgets are enforced; a run lease binds sample/hash/nonce; evidence returns from the guest; disposal/rollback is independently verifiable. If Windows Sandbox cannot supply the required rollback attestation, use the already authorized Hyper-V route or leave F08 explicitly partial.

- [ ] Extend the benign Sandbox probe into guest qualification only; keep target execution disabled until qualification, lease, and rollback checks pass.
- [ ] Build the handoff/collector from existing `DynamicLabHandoff`, `RunLease`, VM qualification, and rollback schemas instead of introducing duplicate contracts.
- [ ] Use only a benign licensed/public corpus sample for the first dynamic campaign; never run an unknown sample on the host.
- [ ] Run focused tests for invalid guest, missing snapshot/rollback, nonce mismatch, network-on, timeout, cleanup failure, and evidence tampering.

### Task 5: Measure and expand profile capability (F03–F11)

**Acceptance:** each profile has an authorized disjoint corpus, ground truth independent from the implementation author where feasible, denominators, false positives/negatives, confidence intervals, calibration, and a documented unsupported boundary.

- [ ] Fix the observed high false-positive rate in binary relation/symbol-candidate scoring on the current holdout before adding more samples.
- [ ] Bring F03 to at least 10 independent complex authorized projects with real oracles, disjoint development/calibration/holdout splits, and source/license/hash provenance; use only in-scope corpus and acquire only missing families.
- [ ] Expand Onda 0 profiles first; then add .NET, Android, and WASM; then Mach-O, JVM, and firmware only when a real backend and maintainable holdout exist. Certify each format/architecture separately.
- [ ] Run adversarial/fuzz/symbolic campaigns only when a harness exists and results can change a gate; label static seed generation or external solver artifacts as such, not as dynamic execution.

### Task 6: Clean replay and release certification (F00–F12)

**Acceptance:** fresh offline install and full suite pass in two clean environments; release manifest lists exact commit, toolchain/corpus locks, gates and artifact hashes; one independent reviewer reproduces the gate; all required gates are `QUITADA` before universal completion is claimed.

- [ ] Run the full suite once from the clean replay candidate and once from a second fresh environment; retain JUnit and concise logs.
- [ ] Recompute toolchain/corpus locks, SBOM, licenses, release evidence and F00–F12 gates from actual artifacts.
- [ ] Perform one independent review on the frozen candidate, correct findings, and rerun only affected tests plus the full release suite if code changes.
- [ ] Emit `release-certification.v1`; exit 0 only when all required gates pass, otherwise retain partial status and a finite debt list.

## Stop/Continue Rule

- Continue automatically while work is local, authorized, reversible, and evidence-backed.
- Stop a profile from promotion when the required tool, license, corpus, guest, rollback, oracle, or reviewer evidence is absent; continue other independent profiles.
- The completed product may be called high-confidence only within its measured profile and input envelope. Reconstructing mathematically lost source or proving behavior for arbitrary future inputs is outside any valid acceptance claim.

