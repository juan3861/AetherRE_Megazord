# Observed native frame address prefixes

The optional observed-address route derives a conditional frame program from
the target's PE bytes and revalidated High P-Code/HighSymbol inputs. It does not
require a supplied address fact. The object extent is still requested explicitly.

```powershell
megazord.py ghidra-decompile owned.dll --observe-frame-function owned_pair_caller --frame-object-bytes 16 --frame-language-dir path\to\x86\data\languages --out new-report.json
megazord.py universal owned.dll --out new-case --native-reconstruction --observe-frame-function owned_pair_caller --frame-object-bytes 16 --frame-language-dir path\to\x86\data\languages
```

MCP `aether_ghidra_decompile` accepts the same trio as `observe_frame_function`,
`frame_object_bytes`, and `frame_language_dir`. The directory must contain declared
`ia.sinc`, `x86.slaspec` and `x86-64.slaspec` bytes. Their hashes identify inputs;
they do not authenticate a compiled language, acquisition or installed toolchain.

The initial domain is Windows x86-64 PE, one straight-line High-IR block and one
direct call. The observer binds the ambient RSP register, matches operation PCs
to actual decoded instructions, and tracks 64-bit MOV/LEA/RSP adjustments through
RCX/RDX/R8/R9 argument positions. A LEA result may reach the argument through a
64-bit register copy. Narrow copies, unknown origins/instructions, branches,
unbacked or ambiguous PE mappings and identity disagreements refuse.

Native code extent comes from the actual bounded PE exception table and file
sections; no caller-provided machine inventory certifies the bytes. Header and
section mappings must be disjoint. The observer covers at most4096 function bytes
and128 decoded instructions. It reports the native code/prefix hashes, file
offset, function range, role PCs, IR/HighSymbol digests and declared-language hashes.
Preferred image addresses do not establish an ASLR process snapshot.

Input budgets are32MiB for target bytes,4MiB per declared language file and an
object extent of1–4096 bytes. Stable bounded reads precede the backend. Local
create-only snapshots preserve the target and all three language files; their
receipt remains outside the derived program. The raw CLI places the bundle next
to explicit JSON output, or in a private temporary directory when no output path
is supplied. MCP uses a private temporary bundle. Universal cases retain the
bundle under `observed_frame_inputs`. These are local hashes, not external custody.
The observed route also retains its Ghidra export and reports its directory and
artifact hashes, so the original IR inputs remain available for review and replay.

The options are required together and conflict with supplied-frame hypotheses,
memory/call-model and PDB/DIA options. JSON output retains the proof limits;
direct `.c` output is refused. The explicit JS adapter refuses the request.
Universal requests may also ask for ordinary native reconstruction; consumers
share one export. An unsupported observed profile has zero attempted programs
while retaining any actual export inventory used by the other consumer.

Observation failures preserve input receipts and refuse model generation. CLI
JSON output retains a failed observation report, MCP returns an explicit failure,
and universal cases publish a separate refused derived result with honest counts.
Existing requests without the observed-address options preserve their defaults.

`native_address_prefix_observed=true` means a bounded caller-address relation
under the declared layout and Windows x64 model assumptions. It does not prove
callee effects or extent, object lifetime, borrowed-return validity, callbacks,
control flow after the call, a complete native frame, recovered ABI, equivalence,
original-source identity or native call-profile admission. Those flags remain
false. Pseudo-source is not original source; development tests are not homologation.
