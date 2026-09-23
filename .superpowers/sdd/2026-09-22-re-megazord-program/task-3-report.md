# Task 3 Report - Evidence Kernel and Intake

Date: 2026-09-22
Status: PARCIALMENTE QUITADA

## Delivered commits

- `0c93e09` - freeze forensic kernel contracts
- `7f03987` - enforce kernel contract constructors
- `da38b08` - harden kernel contract boundaries
- `bd04705` - content-addressed evidence store and durable journal
- `f8c1678` - bounded intake, safe walk, archive intake, and deterministic profile routing
- `ea4033e` - worker lifecycle v2 and kernel evidence validation
- `db98603` - chaos/replay tests and Evidence Kernel operator documentation
- `5ff8d49` - backward-compatible AnalysisReport kernel metadata

## Verification performed

All pytest commands used CPython 3.13 with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`.

1. Kernel/front focused gate:

```text
python -m pytest tests/test_kernel_contracts.py tests/test_evidence_store.py tests/test_evidence_journal.py tests/test_archive_intake.py tests/test_intake.py tests/test_profile_router.py tests/test_worker_contracts_v2.py tests/test_kernel_evidence_contract.py tests/test_pipeline_kernel.py tests/test_intake_cli.py tests/test_kernel_chaos.py tests/test_kernel_replay.py -q
36 passed in 3.27s
```

2. Brief compatibility gate:

```text
python -m pytest tests/test_evidence_contract.py tests/test_custody.py tests/test_safe_walk.py tests/test_checkpoint.py tests/test_process.py tests/test_process_cleanup.py tests/test_intake.py tests/test_profile_router.py -q
26 passed in 3.91s
```

3. Fault campaigns (run with repository root in `PYTHONPATH`; the first tool also requires its documented `--out` argument):

```text
tools/f02_fault_campaign.py --out output/f02_kernel/fault_campaign.json
status=complete_for_injected_local_profile; passed=8; failed=0

tools/f02_commit_crash_campaign.py
status=pass_commit_boundary_recovery; ready_seen=true; child_exit=1
```

These campaigns prove only their injected local profile, not physical ENOSPC, physical power loss, external anchoring, or WORM custody.

## Scope and debt

- Full repository suite: **NAO COMPROVADA** in this finalization turn, by instruction not to wait on the full suite.
- Pipeline and CLI behavior passed their focused tests in the current working tree. Their source files contain pre-existing, unrelated uncommitted work interleaved with the Task 3 hunks; those broad files were deliberately not staged wholesale to avoid capturing user/other-front changes.
- `README.md` likewise contains unrelated pre-existing edits; the dedicated operator document is committed at `docs/EVIDENCE_KERNEL.md`.
- F02 project-level phase-gate promotion is **NAO COMPROVADA**; no universal/project-complete claim is made.

Continua em divida: isolate and commit only the pipeline/CLI Task 3 hunks, or first land the other owners' interleaved changes, then run the full clean suite and materialize the phase-gate evidence bundle.

## Fix round 1 - 2026-09-22

Status: QUITADA para os tres findings desta rodada.

Correcoes:

1. `validate_worker_result` agora exige que todo envelope de evidencia use exatamente o `input_artifact_id` e SHA-256 do `WorkerPlan`; divergencia falha com `worker_evidence_artifact_mismatch`.
2. `IntakeTransaction` acumula os bytes admitidos por todo o caso. O container e os membros extraidos compartilham `max_total_bytes`; a rejeicao ocorre antes da publicacao do membro excedente.
3. `recover_interrupted_tail` valida o prefixo sem alterar o journal vivo, grava e sincroniza a quarentena antes do commit, publica o prefixo recuperado por `os.replace` e restaura journal/head em caso de falha normal no commit do head. Testes injetam falha no replace e no commit do head.

Prova focada, com `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`:

```text
python -m pytest tests/test_worker_contracts_v2.py tests/test_contracts.py tests/test_evidence_journal.py tests/test_intake.py tests/test_archive_intake.py tests/test_evidence_store.py -q
15 passed in 1.82s

python -m pytest tests/test_kernel_contracts.py tests/test_evidence_store.py tests/test_evidence_journal.py tests/test_archive_intake.py tests/test_intake.py tests/test_profile_router.py tests/test_worker_contracts_v2.py tests/test_kernel_evidence_contract.py tests/test_pipeline_kernel.py tests/test_intake_cli.py tests/test_kernel_chaos.py tests/test_kernel_replay.py -q
40 passed in 6.11s
```

A divida intercalada de pipeline/CLI registrada acima permanece inalterada e fora deste commit.
