# Observed INDIRECT effect references

The optional function field `indirect_effect_observation` records Ghidra's
post-decompilation resolution of internal INDIRECT references. It is separate
from raw `ghidra-high-pcode.v1`; the raw operation inventory stays unchanged.

`observed-indirect-effects.v1` binds target SHA256, function address and exact
raw IR file SHA256. Entries preserve every INDIRECT in IR inventory order,
its reference varnode and numeric reference id, and one status:

- `resolved`: `HighFunction.getOpRef` returned an operation present in the
  exported inventory; identity, opcode and full sequence are recorded.
- `unavailable`: the lookup returned no operation.
- `outside_inventory`: the returned operation was absent from the export.
- `reference_out_of_range`: the reference cannot be represented by the API's
  unsigned32 reference-id transport.

The consumer validates counts, entries, identities, sequences, budgets and
the raw IR digest. `complete` covers only reference-resolution inventory.
`alias_semantics_proved` and `call_semantics_proved` remain false. An empty
complete inventory records zero INDIRECT operators; an absent optional field
remains absent, without a synthetic observation.

Admitted metadata has a mutation digest. Selection and IR preview verify it
again; previews expose bounded counts and selected reconstruction exposes the
observation. These paths retain existing refusal of unmodeled INDIRECT effects.
The field does not authorize COPY substitution, causal reordering, frame
allocation, alias resolution or target execution.

This prerequisite supports later native/IR frame correspondence, shared memory
and lifetime modeling. Producer observation is distinct from actual memory
effects, native trace, independent oracle and homologation. Pseudo-source is
not original source.
