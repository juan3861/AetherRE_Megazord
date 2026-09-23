# Clean install, replay and F00--F12 release gate

## What the release gate proves

`tools/f12_universal_release.py` is a conservative **aggregator**, not a test
runner or certification authority. It lists all thirteen gates, hashes each
JSON input it actually reads and approves the release only when every gate is
`QUITADA` with `evidence_valid: true`. Missing, duplicate, malformed,
out-of-root or contradictory input remains explicit debt.

A green unit suite alone does not prove a clean install, a replay, a real VM,
an independent review, or any F00--F12 gate.

## Fresh offline replay procedure

1. Start from a newly created directory outside the development checkout.
2. Verify the source archive, dependency lock and wheelhouse against their
   separately delivered SHA-256 manifest. Do not inherit the developer venv.
3. Create a Python 3.13 virtual environment and install with network disabled,
   using only locked, hash-verified wheels.
4. Run the complete suite and emit JUnit. Record failures, errors and all
   skips; a skipped mandatory VM, physical fault or blind-holdout exercise is
   debt even if pytest exits zero.
5. Run the bounded chaos/adversarial campaign, clean replay and real-VM probe.
   Unknown targets must never execute on the host. F08 requires material VM,
   rollback and network-isolation evidence; WSL, a mock or a declaration is
   insufficient.
6. Recompute every produced artifact hash. Create one gate row only after its
   native validator has accepted the underlying artifact.
7. Have an independent reviewer reproduce the procedure in another fresh
   workspace. Unresolved differences keep the affected gate non-passing.

## Accepted aggregator input

Each `--evidence` file is UTF-8 JSON under `--root` and may contain `gates`,
`rows`, or a compatible `phase-gate-report.v1` `phases` array. A direct gate
row has this minimal shape:

```json
{
  "gate": "F08",
  "status": "NAO_COMPROVADA",
  "evidence_valid": true
}
```

`evidence_valid` means that the producer validated its native evidence; it is
not a waiver for a non-`QUITADA` status. For phase-gate reports, the aggregator
requires a non-empty evidence list, every item `verified: true`, and no row
errors. Duplicate rows invalidate that gate rather than applying last-write
wins.

## Commands

```powershell
$python = 'C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1' # only if a host plugin is incompatible
& $python -m pytest -q --junitxml=output/f12_final.junit.xml

& $python tools/f00_clean_replay_v2.py

& $python tools/f12_universal_release.py `
  --root D:\AetherRE_Megazord `
  --evidence output/f12_phase_gate_report.json `
  --output output/f12_universal_release.json
```

Exit code `0` is reserved for all thirteen validated `QUITADA` rows. Exit code
`3` means a valid partial report was written. Exit code `1` means the report
could not be written or another operational input error occurred.

## Mandatory debt record

Until current artifacts prove otherwise, report all of the following rather
than claiming completion:

- **full suite:** not proved by focused Task 7 tests;
- **F08/VM:** real disposable VM, rollback and isolation remain unproved when
  the qualification artifact is absent or non-passing;
- **clean replay:** fresh offline installation and byte/hash comparison remain
  unproved until executed outside the working tree;
- **external review:** implementation by its author is not independent review;
- **missing gate evidence:** every absent F00--F12 row remains
  `NAO_COMPROVADA` in the generated release report.

The only completion signal is `gate_passed: true` in a reproducible
`universal-release.v1` report containing F00 through F12. Otherwise the
release is **PARCIALMENTE_QUITADA** and continues in debt.
