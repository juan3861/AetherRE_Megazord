# Observed INDIRECT references implementation plan

> **For agentic workers:** Use superpowers:executing-plans. Keep producer observation distinct from semantics; independent reviewer quota remains unavailable.

**Goal:** Preserve explicit Ghidra resolution of INDIRECT internal effect references before attempting frame/alias modeling.

**Architecture:** Optional function sidecar `observed-indirect-effects.v1` binds raw IR file SHA256, target/function, each INDIRECT/reference varnode and resolved operation identity/sequence. Producer uses HighFunction.getOpRef; consumer validates inventories/digests/budgets. No raw IR schema changes and no admission of INDIRECT in generated C.

**Tech Stack:** Existing Java Ghidra exporter, Python3.13 bridge/validator, portable own IR fixtures, governed static Ghidra worker.

- [ ] Back up current Java exporter, bridge and phase map under F:/AetherRE_Audits/aetherre-20261102/indirect-effects; preserve the1591receipt.
- [ ] RED portable validator tests: resolvedCALL/STORE, absent/unresolved/outside/range, duplicate/missing entries, wrong target/function/IR/varnode/reference/effect/sequence, fabricated complete/semantic flags, budgets and mutation. Synthetic test observations are not live producer proof.
- [ ] Implement a strict validator in aether_re/indirect_effects.py and map it F05 immediately. Denominators are recomputed; incomplete resolution stays incomplete. Bind IR bytes via evidence SHA, and attach observation digest.
- [ ] RED bridge tests for optional load, no-IR rejection, unchanged absence, selected/preview exposure, post-admission mutation and preserved reconstruction refusal. Integrate only optional metadata, preserving old raw IR/model behavior.
- [ ] Producer resolves references with actual getOpRef; records resolved/unavailable/outside_inventory/reference_out_of_range, exact identity/sequence and rawIRsha. Inline sidecar <=256KiB, existing aggregate summary budget still enforced.
- [ ] Static actual own Od/O2 exports via governed worker; verify all observed reference links, raw IR whole equality, selectedCLI/MCP/universal exposure and refusal retained. Never run analyzed DLL.
- [ ] Review scope, focused regression, old profile whole preservation, frozen full suite, terminal seal and after-exit rehash. Independent final/human review remains explicit debt.

No frame/alias effect is proved by complete reference observation. Continue the larger frame transport plan and all original F00-F12 requirements afterward. No gate/certificate promotion.
