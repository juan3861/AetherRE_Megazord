# Observed frame transport implementation plan

> **For agentic workers:** Use superpowers:executing-plans task-by-task. Parallel reviewer quota is exhausted; record independent-review debt without substituting author review.

**Goal:** Extend the existing reconstructor toward verified caller-owned frame memory, preserving the full F00-F12 engineering objective.

**Architecture:** First prove native-instruction/IR address relationships against target bytes and observed metadata. Then supply a bounded private frame object per invocation to the existing sparse-memory/call runtime, with shared aliases, explicit lifetime and three-state cleanup. No invented source formal, original ABI claim or blanket admission of ambient inputs.

**Tech Stack:** Python3.13, existing High P-Code validator, Capstone static decode, existing generated C sparse memory/call/effects runtime, own source/MSVC/native/Unicorn differential.

Authoritative predecessor: stack-abi/AFTER_STACK_VALIDATION_HANDOFF.md and frozen frame-frontier/NEXT_FRAME_REQUIREMENTS.md under F:/AetherRE_Audits/aetherre-20261102. Do not modify sealed public-integration artifacts. Heavy new output stays on F. No destructive Git operations or automatic gate promotion.

- [ ] 1. Native/IR correspondence proof. Create tests first in F:/AetherRE_Audits/aetherre-20261102/frame-proof for observed own caller. Refuse changed PC, offset, register identity, code bytes, context, callee, branch, stack bounds, unmodeled operations. Bind native target bytes, IR payload, HighSymbol observation and local register-layout evidence. Return only an address fact, never reconstruction admission. Preserve RED and GREEN results.
- [ ] 2. Generalize proof over supported straight-line paths and branch joins with agreement; reject unsupported instructions and ambiguous control flow. Compare against own native/emulator traces and independent symbolic arithmetic. Missing coverage stays explicit. Add exact machine-byte snapshots and reusable contract to the existing code only after prototype review.
- [ ] 3. Private-frame runtime. RED collision, overflow, overlap, alignment, nested invocation, capacity exhaustion and lifetime tests. Allocate backing bytes per invocation, distinguish shadow/object intervals, and release on every runtime state. External sparse-memory regions remain authoritative; no hidden alias or preexisting region overwrite.
- [ ] 4. Alias and escape analysis. Address-taken stack SSA must read/write the same frame object as callees. Reject divergent copies, unproved pointer arithmetic, frame address return/storage escape and unsupported indirect/recursive calls. Test actual effects and cleanup, not only scalar return.
- [ ] 5. Bound formal/return transport. Preserve observed HighSymbol formal ordering and hidden-return observations separately from inferred source types. Validate call slots, widths and native argument location at each admitted site. Explicit opt-in profile until full ABI evidence exists; prior profiles unchanged.
- [ ] 6. Integrate existing call_closure/ghidra_pcode_c/call_runtime contracts and existing CLI/MCP/universal. Add phase-map coverage with the module. Expose precise proofs, hypotheses, budget/refusal denominators, target/IR/context digests and false ABI/source-arity/equivalence flags.
- [ ] 7. Differential qualification. Same own source/build bytes across native/emulator/generated C, actual frame memory effects, nested calls, multiple frames and failure states. Then broader authorized external families and architectures; own fixtures do not become independent oracle or blind holdout.
- [ ] 8. Review/freeze/regress/seal. Review new scope, preserve old whole reports, freeze source/support/runtime/fixtures, run appropriate full regression, wait real terminal, seal create-only, rehash after exit, append live ledger. Independent final review and human homologation remain required.

No finite step completes the global goal. All declared profiles, source/build/machine/trace correlation, independent corpus/holdout/calibration, governed VM boot/nonce/restore, replay/load/chaos, WORM and human homologation remain obligations.
