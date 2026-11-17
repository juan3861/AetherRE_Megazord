# Conditional frame programs in a universal case

The universal static pipeline accepts an explicit frame hypothesis for one
selected function:

```powershell
megazord.py universal owned.dll --out new-case --derive-frame-function owned_pair_caller --frame-fact fact.json
```

The hypothesis must name the admitted target's `target_sha256`. It remains a
supplied hypothesis: pseudo-source is not original source, and a complete derived
model does not establish a native frame layout, recovered ABI, binary equivalence,
native call-profile admission, or release certification.

The pair of options is required together. Memory/call-model and PDB/DIA options
conflict with frame derivation. The explicit JavaScript adapter path rejects the
request before starting its worker. `--native-reconstruction` may be combined
with derivation without those conflicting options; both consumers then share one
static export of the admitted target snapshot.

Before target intake, the pipeline checks static authorization and reads the
hypothesis as strict UTF-8 JSON, bounded to 65,536 bytes. It rejects duplicate
keys and nonfinite numbers. After target intake it publishes the exact original
hypothesis bytes as `derived_frame_fact.json`, checks the preflight byte hash,
and rereads the snapshot. A changed hypothesis or target-hash mismatch refuses
before starting the backend. Local hashes do not provide external WORM custody.

`derived_frame_program.json` contains a separate `derived-frame-case.v1` result.
Its denominator is one requested program, regardless of the number of functions
in the export. Unsupported profiles and backend failures have zero attempted
programs. A selected but unsupported model has one attempted and one refused
program. A complete model has one derived program. The result preserves model
refusals and never changes the case's certification or dynamic-execution status.

The JSON body, including its final newline, is bounded to 8 MiB in UTF-8 and is
published without overwriting an existing file. The case report adds a separate
`publication` receipt with that file's path, byte count and SHA-256; the published
body does not contain its own hash. Without a frame request, the optional
`derived_frame_program` key is omitted from the case report.

The program reader still checks the selected functions' identities and observed
IR bindings. These checks establish the provenance of the inputs consumed by the
conditional model, not the truth of the supplied native-frame relation. Tests
with a stub backend, historical-export replay, a fresh Ghidra run, native
behavioral trials, and independent homologation are distinct evidence levels.
