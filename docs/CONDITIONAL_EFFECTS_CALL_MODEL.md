# Conditional direct calls with shared abstract-byte effects

`bounded-direct-effects-calls.v1` is a separate opt-in development profile over
`bounded-bytes.v2`. It composes admitted observed High P-Code with direct calls,
LOAD and STORE. `complete` means that conditional translation completed. It
does not establish original machine call semantics, recovered ABI, original
parameter count, source identity or binary equivalence. Pseudo-source is not
original source. This API does not compile generated C or execute target bytes.

Use `ghidra-decompile --memory-model bounded-bytes.v2 --call-model
bounded-direct-effects-calls.v1 --reconstruct-function FUNCTION`. MCP takes the
same values in `memory_model`, `call_model` and `reconstruct_function`.
Universal takes `--native-reconstruction --native-memory-model bounded-bytes.v2
--native-call-model bounded-direct-effects-calls.v1`. It retains the requested
call model even for unsupported profiles. Invalid configuration stops before
the native worker. The pure profile and default CALL refusal remain distinct.

The target/export snapshots, hash/identity/HighSymbol admission, executable
file-backed block mapping, finite graph/width/formal/return/halt checks and
closure quotas remain in force. Every memory selector must name the same
default byte-addressable memory space. CALLIND, CALLOTHER, INDIRECT, persistent
storage, recursive call graphs and unsupported stack/return forms remain
refused. IR without an effect is not proof that the original binary lacks it.
Local admission is not a signed producer attestation.

Private definition-only stack SSA values retain the no-input/no-pointer-
arithmetic domain. In this effects profile, reused byte ranges additionally
require bounded backward liveness with phi inputs placed on their incoming
edges. Simultaneously live overlaps, unknown/unresolved dataflow and proof
budget exhaustion are refused. Published per-function reuse summaries bind
the IR payload and fixed-point facts; they prove only this private SSA
noninterference property. Physical stack addresses, escaped aliases and
original frame/ABI remain unproved. The pure profile keeps spatial disjointness.

## Three runtime states

Generated functions take memory, calls and effects pointers, then scalar input
transports. Callers supply valid nonaliasing states/buffers and explicit initial
abstract bytes. These pointers are host infrastructure, whereas modeled pointer
arguments are abstract addresses. The runtime does not authenticate process
memory or make hostile host pointers safe. Compile the outer
`structured_c_source`; `ctree.structured_c_source` is a function fragment.

The existing sparse byte and call runtimes retain their event structures. The
new operation-start trace has capacity/count/last_step/context/status and a
caller-owned array of `aether_effect_event`. Capacity is at most1,000,000events;
zero capacity is allowed and causes a trace-budget failure at the first start.
Its status is0 success,1 invalid state/context or2 trace budget. Memory/call
status dictionaries remain in the report. **A result is valid only when all
three statuses are zero.** A null state is an invalid caller precondition.

Start one root invocation with fresh zero-count history: memory events/steps executed,
call count/events/depth, and effect count/last_step are zero; the effects context
is unused and zeroed. An admitted root binds the effects state to the call
context fingerprint. Callees share all three states; none resets the budget or
trace. The fingerprint includes the selected profile, immutable members and
all chosen runtime hashes. Reusing a completed effects root or presenting
unexplained prior steps fails. Clearing failure status is not valid replay.

Every original operation or empty block first passes poll/shared-step admission,
then appends its start, then performs semantics. The event stores global step,
function index, local operation index (or empty-block index), kind1 operation
or2 empty block, and the memory/call event counts before it. It records an
admitted start, not successful completion. These counters, the retained event
streams and final runtime states permit an ordered join across nested calls.
The trace is High P-Code steps, not machine instructions or elapsed time.

Memory events in this profile use token `function_index*1024+operation_index`.
`effect_model.memory_operations` maps each token to function identity, original
PC/block, operation, kind and width. This separates equal local indexes in
different callees. The existing pure profile retains its original token scheme.
Static closure counts in `effect_model` differ from root-only static counts in
`memory_model` and from dynamic event counts when loops execute.

If trace capacity ends before STORE/CALL, the tick may be consumed but that
effect does not occur. If it ends after an earlier write, those bytes remain
changed and the overall result is invalid. No rollback is implied. A callee's
effects-state failure invalidates an otherwise-ok call state before existing
leave/unwind logic runs, preserving partial traces and unwinding entered depth.
Memory faults, call/step/trace budgets and cancellation/deadline retain their
own channels. Trusted poll must be bounded and must not mutate runtime states;
without poll there is no wall-clock deadline claim. Use an external process
supervisor when compiling/running generated models.

## Current proof boundary

Execution16 local tests cover admission, isolated trace state, generated shared
byte writes, caller reads before/after aliased callee writes, exact joined
provenance and partial faults under own /Od and /O2 drivers. They are synthetic
IR/model tests. They do not prove that the fixture bytes have those semantics.
The real owned binary/source/Ghidra differential campaign, real clients, wider
loop/void/nested cases and current global regression must be established
separately before calling this increment development-verified.

Execution15's1509passed regression covers its source snapshot, not execution16.
Its optimized owned loop still has a void High P-Code return despite scalar
source return; no missing return is fabricated here. External corpus/oracle,
blind holdout, complete ABI/effects/stack/calls, original machine traces, VM
restore, WORM, hermetic replay/load/calibration and independent human review
remain obligations of the active F00-F12 goal. No gate or certification is
granted by this profile or these tests.
