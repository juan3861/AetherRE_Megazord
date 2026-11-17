# Scoped arenas for the conditional derived C model

Add an opt-in runtime composed with the existing sparse-memory/frame helpers.
The context is caller-owned valid nonaliasing storage, zero-initialized once.
Choose free aligned intervals within a bounded domain; require at most16 live
scopes and128total regions. Issue monotonically increasing nonzero tokens and
refuse exhaustion. Bind scopes to context/memory and require LIFO and exact token.

Snapshot active and saved descriptor shapes, space/events/capacity and arena
geometry. Compare them at nested entry and leave. On a matching top-scope leave,
restore the saved descriptor pointer/count and pop even when fencing fails; set
invalid-state status and preserve the first existing error. Wrong tokens/order
refuse without popping. Proper later cleanup must work with nonzero status.
Never leave memory pointing to the destroyed local scope table after cleanup.

This guards declared descriptor shapes, not arbitrary invalid C pointers or
corruption of the context/scope bookkeeping itself. All metadata addresses and
buffers remain valid/nonaliasing caller preconditions. No arbitrary callback
isolation, pointer provenance, native stack/ABI, escaped-address lifetime or
binary equivalence follows. No gate or native admission may be promoted.

First demonstrate missing runtime through native scenario tests, then implement
and compile it with the literal symbolic-body sparse helpers. Cover nesting,
tokens/order/replay/exhaustion, descriptor/context mutation, error-preserving
cleanup, depth/space bounds. Then bind runtime and checked entry arithmetic to
the generated wrapper/IR and validate native behavior before exposing interfaces.
