# Complete local Ghidra/JDK runtime pin

`ghidra-runtime-lock.v1` binds all ordinary files in the two explicitly selected
installed trees. It includes transitive JARs, native libraries, language files,
configuration and JDK modules; pinning only java.exe or Utility.jar is insufficient.
The reference contains canonical relative names, actual byte sizes and SHA-256.

```powershell
megazord.py ghidra-runtime-lock create --out E:\new-runtime-lock.json
megazord.py ghidra-runtime-lock verify --lock E:\new-runtime-lock.json --out E:\new-runtime-check.json
megazord.py ghidra-decompile owned.dll --ghidra-runtime-lock E:\new-runtime-lock.json --out E:\new-export.json
megazord.py universal owned.dll --native-reconstruction --ghidra-runtime-lock E:\new-runtime-lock.json --out E:\new-case
```

Create/verify accept optional `--ghidra-home` and `--jdk-home`; outputs must be new
files outside both trees. These commands execute no worker or target. Creating a
reference reads both complete trees twice. Checking reads every file and performs
a complete final inventory/metadata census. Only file content determines the pin.
The Windows worker domain requires bin/java.exe and actual Ghidra launcher,
Utility.jar and application properties. References omit absolute installation paths.

Installed default aliases are resolved once to physical destinations before
building/checking the reference or preparing a pinned Java command. The configured
aliases and actual checked roots are recorded separately. Java executes from that
physical destination, so retargeting the alias does not silently switch its runtime.
Explicit caller-provided roots keep the strict no-link rule and are not followed.

Limits are20000files,40000filesystem entries,512MiB/file,4GiB total and4MiB of JSON.
Links/reparse points/hardlinks, special files, case collisions, noncanonical names,
overlapping roots, explicit UNC paths, additions/omissions, size/hash disagreements
and unstable reads or inventories refuse. JSON duplicate keys and unexpected schema
fields refuse. No budgets or positive trust flags can be supplied by the manifest.

The optional CLI/universal `--ghidra-runtime-lock` and MCP
`aether_ghidra_decompile.ghidra_runtime_lock` select this reference. The bridge
snapshots its original bytes and checks the exact installed roots used by its Java
command before launch and after termination. Failed checks refuse export success.
It retains the snapshot, both checks, stdout/stderr and export work directory,
including refusal evidence. CLI requires JSON when this option is active. Universal
requires a Ghidra-consuming request and refuses the explicit JavaScript bypass.
Combined native/derived consumers still share one worker/export. Disabled requests
retain existing defaults and do not scan installed bundles.

`worker_execution.runtime_lock` holds the checks and original/snapshot identity.
Raw CLI/MCP also expose `runtime_lock_export`; universal consumers retain their
worker receipt. The private worker directory contains `runtime-verification.json`.
The canonical manifest digest and original raw JSON digest are separate identities.

This is an observed local byte pin. It does not authenticate upstream acquisition,
prove the physical origin of a mounted path, create an immutable runtime snapshot,
prevent change between checks or restore, deny network access, pin OS-loaded DLLs
outside these roots, or establish hermetic/continuous execution integrity. Metadata
checks cannot defeat a writer able to restore bytes and timestamps between checks.
It does not prove analysis quality, equivalence, recovered ABI, native profile
admission, original source, F00-F12 completion or independent homologation.
