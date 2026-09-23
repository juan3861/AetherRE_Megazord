# Universal Pipeline

`megazord universal` is the fail-closed integration path for authorized case
intake, content-based profile routing, normalized evidence, reconstruction, and
case certification.

## Static-only default

```powershell
python megazord.py universal .\sample.wasm --out .\output\case-001
```

The CLI intentionally creates `CasePolicy.static_only()`. It does not execute
the target and does not silently enable adapters or host-side dynamic analysis.
The persisted result is `case_report.json`; an existing report is never
overwritten.

## Evidence and epistemic states

The flow is:

1. `prepare_case()` publishes a bounded, authorized, content-addressed copy.
2. `route_case()` selects a profile from byte signatures or abstains.
3. `run_profile_workers()` converts routing evidence into observations. No
   unpinned external worker is invented or executed.
4. `normalize_observations()` creates `IRDocument` and `forensic-graph.v2`
   projections while retaining evidence references and epistemic state.
5. `verify_reconstruction()` calls the canonical reconstruction engine without
   fabricating function consensus.
6. `certify_case()` uses the static profile certification gate. Without its
   sealed corpus, pinned workers, independent oracle, and measurements, the
   case reports `abstained` rather than claiming certification.

Profile recognition never implies recovery of original source. Every report
therefore retains an explicit `UNKNOWN` original-source observation and
`original_source_recovered: false`.

## Dynamic gate

Dynamic work is separate from static authorization. `CasePolicy.dynamic()`
requires all of the following before a case can even become eligible:

- authorization scope includes `dynamic-execution`;
- a `LabPolicy` passes disposable-VM preflight with blocked network, no writable
  project mount, snapshot, rollback, collector, and resource budgets;
- a materialized `dynamic-lab-runtime-proof.v1` validates and names the exact
  target SHA-256.

Missing or invalid proof raises a refusal before intake or execution. This
repository currently has no trusted VM executor wired to this orchestrator, so
even a valid proof yields `eligible_no_executor`; it never falls back to the
host. Dynamic execution remains **not implemented**, not simulated.

## Honest limitations

- Static worker specifications are not configured by this integration layer.
- The per-case certification denominator is not materialized by a single-file
  invocation, so certification abstains.
- Reconstruction preserves unknown bodies and cannot recover original names,
  comments, build layout, or exact original source.
