# Explicit observed stack-value transport

`bounded-ms-x64-stack-values.v1` is an opt-in conditional reconstruction profile.
It requires `bounded-bytes.v2`, a selected function, a hash-bound AMD64 PE and
an observed `x86:LE:64:default` / `windows` / little-endian64 context. Other call
profiles keep their existing refusal of stack inputs.

When a function has stack inputs, the profile requires complete one-to-one
HighSymbol association for at most16 observed64bit value formals. The first
four must occupy the declared register layout; later formals must occupy8byte
stack cells at offsets40+8*(ordinal-4), with no wrapped ranges or ambiguous
membership. These are immutable supplied values, not addresses of an inferred
machine frame. Private SSA definitions may not overlap their cells. Hidden
return/this/pointer formals and pointer/memory/indirect operations in such a
function are refused by this initial scalar transport contract.

The IR and observed-parameter digests, formal identities/ordinals/locations
and layout hypothesis are recorded in `stack_parameter_proof`; its digest
enters the shared runtime context. Callee argument order still follows bound
formal association, not varnode enumeration order. Sparse memory, shared call
budgets, operation-start events and all three runtime failure states remain.
Caller host buffers/pointers and optional callbacks retain the trusted contract.

CLI: select the profile through `ghidra-decompile --call-model` or
`universal --native-call-model`; MCP uses the `call_model` argument. Availability
in these schemas is distinct from an actual completed worker/corpus run.

Development grounding uses two own six-argument functions from exact builds:
source/native machine leaf, an independent linear-instruction experiment,
Unicorn emulation and generated-C comparison against the same256vectors per
profile. The relevant receipts and statuses are under
`F:/AetherRE_Audits/aetherre-20261102/stack-abi/`. A report marked complete covers
the declared observed-IR model, not original arity or arbitrary program ABI.

Pseudo-source is not original source. ABI recovery, source parameter count and
binary equivalence remain unproved flags; finite own examples are not an
external independent oracle or blind holdout. Full current regression,
independent review, VM restore, WORM and human homologation remain separate
requirements. Inspect dated receipts before making a current completion claim.
