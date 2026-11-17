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

---

## Maximum-ceiling reuse-first execution addendum — 2026-10-12

**Purpose:** maximize defensible extraction and composition of existing engineering components without rebuilding mature parsers/decompilers, while preserving every source tool's provenance and every uncertainty. “Complete” means all declared finite profile envelopes are implemented, integrated, measured, independently reviewed, and certified; it never means exact recovery of arbitrary original source or proof for every future behavior.

### Execution order

1. **Custody and baseline:** retain the existing dirty checkout; capture branch, HEAD, all pending paths, current commands, and prior evidence before each new code change. No reset, clean, checkout, stash, or overwrite of prior evidence.
2. **Reuse inventory and eligibility:** for each candidate component record official origin, exact version, content hash/signature, SPDX license, runtime, supported profile, limits, and actual smoke evidence. Distinguish `candidate → acquired → hash-verified → executed → integrated → profile-tested → certified`; never promote a component because it merely exists on disk.
3. **Reuse-first extraction lanes:** use locked, isolated workers for the formats they demonstrably support. Begin with the already-present REA 6.4.0 JavaScript/Electron adapter and the existing native PE/ELF tools. Add JVM, Android, .NET, WASM, Mach-O, or firmware only after a real worker, license/provenance lock, real sample, oracle, and bounded execution path exist.
4. **Evidence federation, not blind merging:** preserve each engine's raw result and subject hash as separate evidence. Produce a field-level provenance map and `LossLedger`; correlate only fields with validated shared identity/semantics. Until that contract is tested, report `not_attempted` rather than manufacture a merged graph or consensus.
5. **Reconstruction:** label outputs as original source, recovered source, decompiler output, pseudocode, generated candidate, or behavior-tested candidate. Keep source/build/binary links hash-bound; treat compilation and similarity as separate from behavioral equivalence.
6. **Dynamic behavior:** only after VM transport, private-network isolation, disposable disk, lease/nonce, collector, resource limits, and rollback checks pass. Start with an explicitly benign marker; execute no unknown target on the host. A provisioned VM/checkpoint is not proof of an executed trace or rollback.
7. **Corpus and accuracy:** register legal basis, family, hashes, oracle provenance, and split membership. Freeze thresholds before blind holdout; report per-profile denominators, precision/recall, abstention, confidence intervals, parse failures, timeouts, and crashes. Do not use a global percentage to hide weak profiles.
8. **Release:** two clean replays, full tests, current manifests, independent reviewer signature, external immutable custody, and owner promotion decision. Until then report local implementation/testing separately from external homologation.

### Immediate execution slice (start here)

- [x] Run focused REA adapter/CLI tests on the current checkout: 9 passed, 0 failed/errors/skips.
- [x] Recompute the locked worker verification against the actual E: package tree and Node runtime: verified, zero issues.
- [x] Execute a real static-only smoke on a tiny, benign, locally created JavaScript/Electron fixture; bind the immutable input snapshot, worker/runtime identities, process containment result, raw engine output, federated report, and artifact hashes.
- [x] Verify the snapshot and report artifacts independently (16 checks); the tool contract states static-only and the report does not claim cross-engine graph equivalence or a profile certificate.
- [x] The smoke exposed no defect, so conditional TDD repair was not triggered; no production-code change was made in this slice.
- [x] Update this plan's checkpoint, the project Hub note, Florence audit, and SDD progress ledger in the same cycle. This run tests integration only; it does not certify the JavaScript profile, close F-gates, or change the strict 0/13 release ruling.

### Next reuse-integration slice — exact artifact identity, not semantic graph merge

- [x] Add failing tests for a field-level correspondence record joining only the same captured input file by normalized relative path and SHA-256; verify byte length from the snapshot and AetherRE inventory, since REA graph observations do not independently provide a size field.
- [x] Implement `build_artifact_correspondence(...) -> artifact-correspondence.v1`; preserve unmatched/conflicting records and counts, reject duplicate/unsafe identities, and explicitly state that byte identity is not semantic agreement.
- [x] Keep `cross_engine_correlation.status=not_attempted`; no graph nodes/edges, behavior, or source equivalence are merged or inferred by this slice.
- [x] Re-run focused tests, the real worker-backed smoke, artifact hash verification, `selftest`, and the full suite after integration.
- [x] Record new exact-current evidence and update the project note, Florence audit, master plant, and progress ledger. Retain the first smoke bundle as pre-correspondence history; do not rewrite its hashes.

### Finish criteria for this campaign

The technical campaign may be called complete only for an explicitly named finite profile set whose workers are hash-locked and actually executed, whose authorized corpus/oracles and blind holdouts are disjoint, whose outputs retain provenance/loss and uncertainty, whose declared tests/replays pass, and whose independent review/release evidence is valid. Dynamic profiles additionally require a real guest run and demonstrated rollback. Universal arbitrary-program exact source recovery remains outside the attainable claim.


### Resultado do slice de identidade exata — 2026-10-12

As cinco tarefas do slice estão concluídas com teste e execução real: 12 testes focados passaram; o worker REA 6.4.0 revalidou sem issues; smoke real produziu 3/3 correspondências exatas de bytes; verificador local 20/20; regressão integral 828 passed/3 skipped/0 falhas/erros. Evidências e hashes estão no checkpoint e no ledger. Nenhuma fusão semântica foi feita e nenhuma certificação ou gate foi promovido. Próximo passo continua sendo corpora/oráculos para perfis finitos e prova dinâmica em guest real.
### Suplemento de revalidação final — 2026-10-12 17:16 -03

Este registro complementa e **supersede os denominadores de teste anteriores neste ciclo**; não altera o estado de gates. Foram adicionados testes fail-closed para colisão de caminhos por case-folding (`Main.js`/`main.js`), conflito de byte length no inventário AetherRE e ID de nó REA duplicado.

- Focada `tests/test_rea_static_adapter.py tests/test_rea_cli.py`: **15 passed**, 0 falhas/erros/skips, 2,10 s.
- Suíte integral final, Python 3.13.13, plugin autoload desativado: **831 passed, 3 skipped, 0 failed, 0 errors**, 834 coletados, 284,27 s, exit 0. Os três skips continuam sendo duas fixtures Ghidra/`GHIDRA_HOME` e uma fixture MSVC/`MEGAZORD_MSVC_PE_FIXTURE`. JUnit `E:\AetherRE_Evidence\megazord-reuse-ceiling-20261012T2001Z\pytest-full-final.xml`, SHA-256 `06B91BCE56CD8F73E59C04B96CBC2B808E75E5FFD8978ECDECABB3AA57AD9D9B`; log SHA-256 `AF95F333D8C08FCF1DFCCE3E4F2D487143ECE9098303DBEC4F43DFC6350FE614`.
- Revalidação final: `megazord status=0`, `megazord selftest=0`, `compileall=0`, `git diff --check=0`. Worktree continua com 20 registros, branch/HEAD inalterados (`codex/re-megazord-execution` / `42775fc8266f2cf2ff0b4a8dc1833f20dc4db186`). SHA do teste atualizado: `tests/test_rea_static_adapter.py` `CF89BFCE3DB5326D6A10E255EC403F4838ECBC80322965D437C3FFFC9CB0D086`.
- O smoke real e seu recibo 20/20 permanecem válidos porque o código de produção e a amostra não mudaram; o incremento final desta revalidação foi apenas cobertura adicional de teste. Bundle permanece em `E:\AetherRE_Evidence\megazord-reuse-ceiling-20261012T2001Z\`.

**Conclusão limitada:** subfatia de identidade exata implementada, executada e coberta pelos testes locais. Não significa perfil JavaScript certificado, fusão semântica, equivalência comportamental, homologação por terceiro ou evidência WORM. F00–F12 seguem **0/13 QUITADA**, release **PARCIALMENTE QUITADA**; F08/F09, G3/G5, G8/G9 e perfis restantes continuam em dívida.