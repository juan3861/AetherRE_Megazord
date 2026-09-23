"""Motor RECONSTRUCT — pseudo-código a partir de imports/strings/exports (não é o fonte original)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from aether_re.models import Finding, FunctionSketch

# Mapeia APIs Windows → papel semântico
API_ROLES: dict[str, str] = {
    "CreateFile": "io_file",
    "ReadFile": "io_file",
    "WriteFile": "io_file",
    "DeleteFile": "io_file",
    "RegOpenKey": "registry",
    "RegSetValue": "registry",
    "RegQueryValue": "registry",
    "InternetOpen": "network",
    "InternetConnect": "network",
    "HttpOpenRequest": "network",
    "HttpSendRequest": "network",
    "URLDownloadToFile": "network",
    "socket": "network",
    "connect": "network",
    "send": "network",
    "recv": "network",
    "WSAStartup": "network",
    "VirtualAlloc": "memory_alloc",
    "VirtualProtect": "memory_protect",
    "VirtualFree": "memory_alloc",
    "HeapAlloc": "memory_alloc",
    "LoadLibrary": "dynamic_resolve",
    "GetProcAddress": "dynamic_resolve",
    "GetModuleHandle": "dynamic_resolve",
    "CreateProcess": "process",
    "CreateThread": "process",
    "CreateRemoteThread": "injection",
    "WriteProcessMemory": "injection",
    "OpenProcess": "injection",
    "ShellExecute": "process",
    "WinExec": "process",
    "IsDebuggerPresent": "anti_debug",
    "CheckRemoteDebuggerPresent": "anti_debug",
    "NtQueryInformationProcess": "anti_debug",
    "CryptDecrypt": "crypto",
    "CryptEncrypt": "crypto",
    "BCryptDecrypt": "crypto",
    "Sleep": "timing",
    "GetTickCount": "timing",
    "CreateMutex": "sync",
    "WaitForSingleObject": "sync",
}


def _api_short(imp: str) -> str:
    if "!" in imp:
        return imp.split("!", 1)[1]
    return imp


def _role_for(api: str) -> str | None:
    for key, role in API_ROLES.items():
        if key.lower() in api.lower():
            return role
    return None


def build_function_sketches(
    imports: list[str],
    exports: list[str],
    strings: list[str],
) -> list[FunctionSketch]:
    by_role: dict[str, list[str]] = defaultdict(list)
    for imp in imports:
        role = _role_for(imp)
        if role:
            by_role[role].append(imp)

    sketches: list[FunctionSketch] = []

    role_names = {
        "io_file": "file_operations",
        "registry": "registry_access",
        "network": "network_comms",
        "memory_alloc": "memory_management",
        "memory_protect": "memory_protection_or_unpack",
        "dynamic_resolve": "api_resolution",
        "process": "process_execution",
        "injection": "process_injection",
        "anti_debug": "anti_analysis",
        "crypto": "cryptographic_ops",
        "timing": "timing_or_delay",
        "sync": "synchronization",
    }

    for role, imps in sorted(by_role.items()):
        near = [s for s in strings if any(a.split("!")[-1][:6].lower() in s.lower() for a in imps)][:5]
        sketches.append(
            FunctionSketch(
                name=role_names.get(role, role),
                address="unknown",
                imports_used=imps[:20],
                strings_near=near,
                notes=f"Cluster semântico inferido a partir de {len(imps)} import(s).",
                confidence=0.45 if len(imps) < 3 else 0.6,
            )
        )

    for exp in exports[:30]:
        sketches.append(
            FunctionSketch(
                name=exp,
                address="export",
                imports_used=[],
                strings_near=[],
                notes="Símbolo exportado (nome real do binário).",
                confidence=0.9,
            )
        )

    if not sketches:
        sketches.append(
            FunctionSketch(
                name="entry_or_unknown",
                notes="Sem imports/exports mapeáveis — precisa de decompilador (Ghidra).",
                confidence=0.15,
            )
        )
    return sketches


def render_pseudo_source(
    target_name: str,
    file_format: str,
    entry_point: str,
    imports: list[str],
    exports: list[str],
    sections: list[dict[str, Any]],
    strings: list[str],
    sketches: list[FunctionSketch],
    decoded: list[dict[str, Any]],
    disasm_snippets: list[dict[str, Any]],
) -> str:
    lines: list[str] = [
        "/*",
        " * AetherRE Megazord — PSEUDO-FONTE RECONSTRUÍDA",
        " * ------------------------------------------------",
        " * ISTO NÃO É O CÓDIGO-FONTE ORIGINAL.",
        " * É um esqueleto semântico gerado a partir de evidências",
        " * (imports, exports, strings, disasm, decodes).",
        " * Confiança e limitações: ver report JSON.",
        " */",
        "",
        f"// target: {target_name}",
        f"// format: {file_format}",
        f"// entry:  {entry_point or 'unknown'}",
        "",
        "#include <stdint.h>",
        "#include <stdbool.h>",
        "",
        "/* --- secções do binário --- */",
    ]
    for s in sections:
        lines.append(
            f"// section {s.get('name')} va={s.get('va')} "
            f"vsize={s.get('vsize')} raw={s.get('raw_size')} entropy={s.get('entropy')}"
        )

    lines += ["", "/* --- imports observados --- */"]
    for imp in imports[:80]:
        lines.append(f"// import {imp}")

    if exports:
        lines += ["", "/* --- exports --- */"]
        for e in exports[:40]:
            lines.append(f"// export {e}")

    lines += ["", "/* --- strings de interesse --- */", "static const char* OBSERVED_STRINGS[] = {"]
    for s in strings[:40]:
        esc = s.replace("\\", "\\\\").replace('"', '\\"')[:120]
        lines.append(f'    "{esc}",')
    lines.append("    0")
    lines.append("};")

    if decoded:
        lines += ["", "/* --- payloads decodificados --- */"]
        for i, d in enumerate(decoded[:15]):
            prev = str(d.get("preview", "")).replace("\n", " ")[:100]
            lines.append(f"// decode[{i}] chain={d.get('chain')} => {prev}")

    if disasm_snippets:
        lines += ["", "/* --- disassembly (entry) --- */", "void entry_disasm_reference(void) {"]
        for sn in disasm_snippets[:1]:
            for insn in sn.get("instructions", [])[:40]:
                lines.append(
                    f"    // {insn['address']}: {insn['mnemonic']} {insn['op_str']}"
                )
        lines.append("}")

    lines += ["", "/* --- funções/clusters inferidos --- */"]
    for sk in sketches:
        lines.append("")
        lines.append(f"// confidence={sk.confidence:.2f} {sk.notes}")
        lines.append(f"void { _c_ident(sk.name) }(void) {{")
        for imp in sk.imports_used[:12]:
            api = _api_short(imp)
            lines.append(f"    // call {imp}")
            lines.append(f"    // {api}(...);")
        for st in sk.strings_near[:5]:
            esc = st.replace('"', "'")[:80]
            lines.append(f'    // uses_string: "{esc}"')
        if not sk.imports_used and not sk.strings_near:
            lines.append("    // corpo desconhecido — requer decompilação profunda")
        lines.append("}")

    lines += [
        "",
        "int main(void) {",
        f"    // entry point @ {entry_point or 'unknown'}",
    ]
    for sk in sketches:
        if sk.address != "export":
            lines.append(f"    { _c_ident(sk.name) }();")
    lines += [
        "    return 0;",
        "}",
        "",
    ]
    return "\n".join(lines)


def _c_ident(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            out.append("_")
    s = "".join(out)
    if not s or s[0].isdigit():
        s = "fn_" + s
    return s[:64]


def run_reconstruct(
    target_name: str,
    file_format: str,
    entry_point: str,
    imports: list[str],
    exports: list[str],
    sections: list[dict[str, Any]],
    strings: list[str],
    decoded: list[dict[str, Any]],
    disasm_snippets: list[dict[str, Any]],
) -> dict[str, Any]:
    sketches = build_function_sketches(imports, exports, strings)
    pseudo = render_pseudo_source(
        target_name=target_name,
        file_format=file_format,
        entry_point=entry_point,
        imports=imports,
        exports=exports,
        sections=sections,
        strings=strings,
        sketches=sketches,
        decoded=decoded,
        disasm_snippets=disasm_snippets,
    )
    conf = 0.0
    if imports:
        conf += 0.25
    if exports:
        conf += 0.15
    if strings:
        conf += 0.15
    if disasm_snippets:
        conf += 0.2
    if decoded:
        conf += 0.1
    if any(s.confidence >= 0.5 for s in sketches):
        conf += 0.1
    conf = min(conf, 0.85)  # nunca fingir 100%

    findings = [
        Finding(
            engine="reconstruct",
            severity="info",
            title="Pseudo-fonte gerada",
            detail=(
                f"{len(sketches)} clusters/funções, confiança global reconstrução={conf:.2f}. "
                "Não confundir com código-fonte original."
            ),
            confidence=conf,
        )
    ]
    return {
        "function_sketches": sketches,
        "pseudo_source": pseudo,
        "confidence": conf,
        "findings": findings,
    }

# Canonical, cited reconstruction API. Legacy run_reconstruct remains compatible.
from dataclasses import dataclass
from aether_re.ir import IRDocument
from aether_re.kernel_contracts import EpistemicState
from aether_re.models import FunctionConsensus
@dataclass(frozen=True)
class ReconstructionUnit:
 identity:str; name:str; address_space:str; address:str; body:str; epistemic_state:EpistemicState; confidence:float; evidence_refs:tuple[str,...]; losses:tuple[str,...]; alternatives:tuple[dict[str,Any],...]
def build_reconstruction(document:IRDocument,functions:list[FunctionConsensus])->tuple[ReconstructionUnit,...]:
 by_key={(x.address_space,x.address):x for x in functions}; units=[]
 for node in document.nodes:
  if node.kind not in {'function','method','dex_method','jvm_method'}:continue
  found=by_key.get((node.location.space,node.location.value));refs=tuple(sorted(set(node.evidence_refs+(tuple(found.evidence_refs) if found else ()))))
  state=found.epistemic_state if found else EpistemicState.UNKNOWN; losses=tuple(sorted(set(node.losses+(tuple(found.losses) if found else ()))))
  body=(found.pseudocode if found and found.pseudocode and found.evidence_refs else '/* body unavailable: evidence does not establish a reconstructable body */')
  units.append(ReconstructionUnit(node.identity,found.name if found else node.name,node.location.space,node.location.value,body,state,found.confidence if found else 0.,refs,losses,tuple(found.alternatives) if found else ()))
 return tuple(units)
def render_reconstruction(units:tuple[ReconstructionUnit,...],language:str)->str:
 return '\n\n'.join(f'/* reconstruction, not original source; state: {x.epistemic_state.value}; evidence: {", ".join(x.evidence_refs)}; losses: {", ".join(x.losses) or "none"} */\n{x.body}' for x in units)
