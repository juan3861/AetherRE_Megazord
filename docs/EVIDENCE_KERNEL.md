# Evidence Kernel

## Operator contract

Create a case without executing target bytes:

```text
python megazord.py intake <SOURCE> --case-dir <NEW_DIR> --authorization <POLICY.json> --result <RESULT.json>
```

Verify and replay with the Python API:

```python
verify_case(Path(<CASE_DIR>))
replay_case(Path(<CASE_DIR>/manifest.json), Path(<NEW_REPLAY_DIR>))
```

The case layout is `objects/sha256/<prefix>/<digest>` (create-only content-addressed bytes), `journal.jsonl` with `journal.head.json`, `manifest.json`, and `custody-receipt.json`. Archive extraction uses `archive-staging/` only after full hostile-container preflight.

Schemas: `authorization-policy.v1`, `artifact-ref.v1`, `derivation-record.v1`, `evidence-journal-entry.v1`, `universal-intake-manifest.v1`, `profile-decision.v1`, `worker-probe.v1`, `worker-plan.v1`, `worker-result.v1`, and `kernel-evidence.v1`.

Default budgets are 10,000 files, 2 GiB total, 512 MiB per file, depth 3, compression ratio 200, and path length 512. An authorization JSON is explicit, e.g. `{"schema":"authorization-policy.v1","basis":"owner","principal":"local-user","scope":["static-analysis"]}`. Dynamic execution is not authorized by this slice.

Events are ordered `case.opened`, zero or more `artifact.published`, then `case.intake_completed`; failures append `case.intake_failed`. Pipeline completion is appended only after its report and final manifest are durable. A partial final journal line may be recovered into `journal.tail.<sha256>.quarantine`; interior corruption, bad heads, and unknown schemas fail closed. Disk-full and cancellation leave no acknowledged artifact publication.

The router uses bounded signatures and inventory; conflicts return `manual-review` / `UNKNOWN`; no weak match becomes a universal claim. Workers are out of process and their plans/results are strict hostile-input contracts.

## Custody statement

This package proves local hash-chain integrity only. `external_anchor=false`; it is not WORM, notarization, semantic truth, or proof that the analyzed bytes were lawfully obtained. On corruption stop promotion, preserve the directory/quarantine, and investigate from a verified copy.