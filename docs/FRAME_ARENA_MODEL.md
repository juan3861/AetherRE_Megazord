# Conditional invocation arena model

Pseudo-source is not original source. This model does not prove binary
equivalence, native frame layout, ABI recovery, a native profile, or a gate.

Use `--frame-runtime invocation-arena.v1` together with exactly one existing
frame route: `--derive-frame-function` plus `--frame-fact`, or
`--observe-frame-function` plus `--frame-object-bytes` and
`--frame-language-dir`. Both `ghidra-decompile` and `universal` expose this
option. The MCP `aether_ghidra_decompile` tool accepts the matching
`frame_runtime` property. Omission preserves the fixed derived model.
Frame reports require JSON output so their assumptions and receipts survive.

The reader revalidates both selected functions before generation. The generator
retains the relocatable body literally and adds an explicit arena context,
first-fit logical allocation, domain guards and unconditional cleanup after
body return. A successful derivation reports `status: conditional_model`;
the universal report counts one derived program while retaining that status.
It never changes native admission or certification.

The generated entry receives `struct aether_arena_context *` followed by its
scalar parameters. Initialize a zeroed context once with `aether_arena_init`
over a valid sparse memory descriptor, a 16-byte-aligned base and a span of
1 through 4096 bytes within U64. Calls allocate private invocation bytes away
from ambient regions, obtain monotonically increasing nonzero tokens, and
restore the prior descriptor table when the correct top scope leaves.
Maximum nesting is 16 scopes, with at most 128 active descriptors.

The caller must supply valid, nonaliasing context, scope, memory descriptor,
region, event and byte storage and exclusive ownership of that metadata.
Descriptor shape checks do not establish arbitrary C pointer provenance,
isolate malicious callbacks, or support concurrent context mutation. The
runtime detects selected shape changes and preserves an existing body error
during cleanup; it does not prove general escape freedom or native lifetimes.

Native tests compile and execute generated, owned C harnesses only. They do
not execute analyzed target binaries. Local MSVC/SDK/OS dependencies are not a
hermetic or authenticated build environment.

The observed-frame route additionally includes `native_pair_data_observation`.
Its independent `observed` or `refused` status describes a bounded comparison of
ordered word stores/loads and returned RAX for a supported linear caller/leaf.
Native GPR preservation is interpreted through the leaf before RET and applied
to actual pre-CALL values. The model's existing derivation status and generated
C body retain their meaning when this extra observation refuses a projection.
Receipt or export identity failures still reject the request. CLI, MCP and
universal use their verified input snapshots, with a shared reader check of the
target and declared language hashes. Direct reader calls bind in-memory bytes.
The witness carries IR/input hashes and a canonical `witness_sha256` calculated
without that field. Supplied-fact and non-frame routes omit this observation.

Balanced architectural CALL/RET and valid nonoverflowing data addresses remain
assumptions. Flags, faults, final RET control transfer, concurrency, general
lifetimes and complete machine equivalence remain outside this projection.
The additional observation retains false native-admission, ABI-recovery and
binary-equivalence flags. Pseudo-source is not original source.
