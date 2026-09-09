"""Motor DISASM — Capstone (estilo radare2/Cutter) quando disponível."""

from __future__ import annotations

from typing import Any

from aether_re.models import Finding


def _capstone_disasm(
    code: bytes,
    base: int,
    is_64: bool,
    max_insns: int = 80,
) -> list[dict[str, Any]]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32  # type: ignore
    except ImportError:
        return []

    mode = CS_MODE_64 if is_64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = False
    out: list[dict[str, Any]] = []
    for i, insn in enumerate(md.disasm(code, base)):
        if i >= max_insns:
            break
        out.append(
            {
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            }
        )
    return out


def extract_entry_code_pe(data: bytes, is_64: bool) -> tuple[bytes, int]:
    """Extrai bytes no entry point de um PE (best-effort)."""
    try:
        import pefile  # type: ignore
    except ImportError:
        return b"", 0

    try:
        pe = pefile.PE(data=data)
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        base = pe.OPTIONAL_HEADER.ImageBase + ep_rva
        offset = pe.get_offset_from_rva(ep_rva)
        blob = data[offset : offset + 256]
        return blob, base
    except Exception:
        return b"", 0


def run_disasm(data: bytes, is_64: bool = True, file_format: str = "") -> dict[str, Any]:
    findings: list[Finding] = []
    snippets: list[dict[str, Any]] = []

    code, base = (b"", 0)
    if file_format.upper().startswith("PE") or data.startswith(b"MZ"):
        code, base = extract_entry_code_pe(data, is_64)

    if not code and len(data) >= 32:
        # fallback: início do ficheiro (shellcode / raw)
        code, base = data[:256], 0x1000
        findings.append(
            Finding(
                engine="disasm",
                severity="info",
                title="Disasm em offset 0 (fallback)",
                detail="Sem entry point PE fiável; a disassemblar os primeiros 256 bytes.",
                confidence=0.4,
            )
        )

    insns = _capstone_disasm(code, base or 0x1000, is_64)
    if not insns:
        findings.append(
            Finding(
                engine="disasm",
                severity="low",
                title="Capstone indisponível ou sem instruções",
                detail="pip install capstone — ou use adapter Ghidra/Rizin para decompilação real.",
                confidence=0.9,
            )
        )
    else:
        snippets.append(
            {
                "region": "entry_point",
                "base": hex(base or 0x1000),
                "instructions": insns,
            }
        )
        findings.append(
            Finding(
                engine="disasm",
                severity="info",
                title=f"Disassembly do entry point ({len(insns)} insns)",
                detail="; ".join(f"{i['mnemonic']} {i['op_str']}" for i in insns[:12]),
                confidence=0.85,
            )
        )

    return {"snippets": snippets, "findings": findings}
