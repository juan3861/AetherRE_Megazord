# Conditional direct calls: bounded-direct-pure-calls.v1

This opt-in model composes a finite set of observed Ghidra High P-Code
functions. `complete` means translation of that admitted observation completed.
It does not mean the original binary's call semantics, ABI, source parameter
count, stack, types or behavior have been recovered. Pseudo-source is not
original source. No analyzed binary is executed by this API.

Use `ghidra-decompile --memory-model bounded-bytes.v2 --call-model
bounded-direct-pure-calls.v1 --reconstruct-function FUNCTION`. The MCP
`aether_ghidra_decompile` arguments use `memory_model`, `call_model` and
`reconstruct_function`. Universal cases use `--native-reconstruction
--native-memory-model bounded-bytes.v2 --native-call-model
bounded-direct-pure-calls.v1`. Invalid combinations fail before Ghidra starts.
The default reconstruction still refuses CALL.

## Admission and explicit hypotheses

Every member comes from the same target-bound export. The bridge revalidates
the IR, normalized graph and parameter observations; the closure snapshots
them before translation. The target file is reopened and hash checked, and
each original block must lie in initialized, readable, executable, file-backed
bytes admitted by the PE/ELF mapper. Zero-fill and quarantined loader bytes
cannot authorize code. These checks establish local consistency and provenance
within this process; they are not a signed producer attestation and do not
authenticate arbitrary IR constructed by an in-process caller.

Direct targets must resolve inside that inventory. Acyclic graph, member,
operation, variable, byte coverage, output and depth limits apply to the whole
closure, including paths through previously visited DAG members. Return/halt
markers retain their existing refusal rules. Callee return width and observed
formal/operand widths must match. Original HighSymbol ordinal to call operand
slot remains an explicit hypothesis. Input transport order is mapped
separately and cannot be inferred from register names or dictionary order.

The profile rejects LOAD, STORE, CALLIND, CALLOTHER, INDIRECT and persistent
storage. Definition-only disjoint stack SSA values may be modeled as private
function values, with no stack inputs, wrapping/overlapping slots or pointer
arithmetic over those slots. This rule does not recover a machine stack frame,
aliasing, recursion, clobbers, imports, varargs, struct returns or tail-call ABI.
Those profiles require further implementation and independent proof.

Absence of effects in optimized High P-Code does not establish purity of the
original machine function. Decompiler analysis can eliminate effects or a
return value. In the owned validation corpus, `owned_call_loop` compiled with
MSVC `/O2` has a scalar source return but its observed High P-Code return is
void. The model retains that void return. It must not be reported as scalar
source equivalence or silently repaired by inventing an IR value. An explicit,
validated return contract and fresh analysis are separate future work.

## Generated runtime

The emitted C is a conditional model intended for a trusted caller. It requires
valid nonaliasing runtime states and trace buffers; it does not make hostile
host pointers safe. The single sparse-memory state shares the operation budget
across all callees. The call state records caller/callee/site identities,
formal arguments, entry/exit and scalar return. Internal callees are static.
The context SHA binds function snapshots, mappings and runtime implementations;
it fences accidental cross-closure state reuse, not external tampering.

Check both memory and call status before interpreting a return. Memory status
codes remain in `memory_model.status_codes`. Call status is 0 success, 1 invalid
state, 2 depth budget, 3 trace budget, 4 call budget, 5 cancellation observed,
6 deadline observed. Failures preserve partial traces and unwind entered call
depth. Clearing a failure status does not create a valid replay. An exhausted
exit trace can invalidate the result after a callee has run.

An optional poll callback is trusted, bounded infrastructure and must not mutate
the runtime state. It runs before each operation or empty-block step. Without
it there is no wall-clock deadline claim. A process supervisor is still needed
when compiling or running generated C. The public reconstruction API itself
only returns data and source; it does not compile or run them.

## Evidence boundary for execution 15

The preserved owned campaign contains five roots from each of two target build
profiles and two generated-driver optimization profiles, with 356 vectors per
run. Twenty drivers observed 7,120 cases and 27,504 call events. Of those,
6,408 scalar model results matched native recompilation of the exact owned
source and a separately written Python oracle. The 712 void-return cases above
have trace/argument/budget checks only; their source scalar return remains
unmodeled. The analyzed target DLLs were not loaded or executed. Generated
model traces are not original machine traces.

This development evidence is in
`F:\AetherRE_Audits\aetherre-20261030\implementation-15`. The first partial
campaign and its invalid scalar-driver assumption are preserved separately.
External corpus/oracle, blind holdout, complete ABI/effects, source-build-binary
trace, VM snapshot/restore, WORM custody, hermetic replay, load/calibration and
independent human review remain release debts. This document grants no gate,
attestation or certification.
