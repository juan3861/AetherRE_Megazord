# Conditional external-address derivation in direct-effects calls

The explicit bounded-direct-effects-calls.v1 profile can retain pointer values
through private stack SSA slots when bounded derivation proves that every
reachable dependency component leads to an observed pointer formal. This is a
caller hypothesis about abstract byte addresses; it is not recovered original
RAM provenance, source arity, stack-frame layout or machine ABI.

The proof admits width-preserving COPY/CAST, PHI and PTRADD/PTRSUB with constant
offset operands. Unknown inputs, constants as roots, loaded pointers, unsupported
pointer producers, unseeded components and exhausted visits refuse. A good PHI
arm does not authorize another closed unseeded component. Callee address-formal
requirements are checked against caller actual arguments; pointer CALL results
have no provenance summary and remain refused if required as addresses. Validated
IR, definition-only private storage and existing disjointness/liveness admission
remain prerequisites. Runtime bounds, permissions, initialization, budgets and
the three failure states continue to apply. Host buffers/pointers and poll
callbacks still require the trusted caller contract.

Each proof binds IR and observed-parameter digests, roots, sinks and derivations.
Its digest enters the closure fingerprint. The effects translator uses an
explicit Ctree node budget512 for guard-expanded CFGs; this policy also enters
the fingerprint and the Ctree report. Default and pure profiles retain cap256;
the edge/output limits and every operation/call/memory guard remain intact.

Development motivation: upstream Ghidra deobExample.c Od length/deobfuscate keep
formal-derived pointer PHIs in private stack SSA. O2 deobfuscate expands from11
raw blocks to360 guarded blocks, exceeding the old256 cap. A new campaign uses
the exact preserved source and raw IR, with source C recompilation plus a
separate Python oracle. Its results, complete denominator, refusals and source
hashes are recorded in F:/AetherRE_Audits/aetherre-20261102/current-external.
The source was inspected and is DEVELOPMENT, not blind holdout. Harness/oracle
authorship is not external independent adjudication. Check the current receipt
and full regression before treating any development result as current.

Pseudo-source is not original source. No original binary equivalence, human
homologation, WORM, VM restore or global F00-F12 gate follows from this profile.
