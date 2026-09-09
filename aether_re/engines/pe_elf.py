"""Motor STRUCTURE — PE (estilo Ghidra/Cutter triage) e ELF básico."""

from __future__ import annotations

import struct
from typing import Any

from aether_re.models import Finding


def _try_pefile(data: bytes) -> dict[str, Any] | None:
    try:
        import pefile  # type: ignore
    except ImportError:
        return None

    pe = pefile.PE(data=data, fast_load=False)
    pe.parse_data_directories()

    imports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore") if entry.dll else "?"
            for imp in entry.imports:
                name = (
                    imp.name.decode(errors="ignore")
                    if imp.name
                    else f"ord_{imp.ordinal}"
                )
                imports.append(f"{dll}!{name}")

    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode(errors="ignore"))
            else:
                exports.append(f"ord_{exp.ordinal}")

    sections: list[dict[str, Any]] = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="ignore")
        sections.append(
            {
                "name": name,
                "va": hex(s.VirtualAddress),
                "vsize": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": round(s.get_entropy(), 4),
                "chars": hex(s.Characteristics),
            }
        )

    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase
    machine = pe.FILE_HEADER.Machine
    is_64 = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS

    findings: list[Finding] = [
        Finding(
            engine="structure",
            severity="info",
            title="PE analisado",
            detail=(
                f"{'PE32+' if is_64 else 'PE32'} machine=0x{machine:X} "
                f"EP=0x{entry:X} ImageBase=0x{image_base:X} "
                f"imports={len(imports)} exports={len(exports)} sections={len(sections)}"
            ),
            confidence=0.95,
        )
    ]

    # Heuristics
    exec_rw = [
        s
        for s in sections
        if int(s["chars"], 16) & 0xE0000000 == 0xE0000000  # rough
        or (int(s["chars"], 16) & 0x20000000 and int(s["chars"], 16) & 0x80000000)
    ]
    high_ent_code = [s for s in sections if s["entropy"] >= 7.0 and "text" in s["name"].lower()]
    if high_ent_code:
        findings.append(
            Finding(
                engine="structure",
                severity="high",
                title="Secção de código com entropia alta",
                detail=", ".join(f"{s['name']}={s['entropy']}" for s in high_ent_code),
                confidence=0.7,
            )
        )

    # Suspicious APIs
    suspicious_keywords = (
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "LoadLibrary",
        "GetProcAddress",
        "WinExec",
        "ShellExecute",
        "URLDownloadToFile",
        "InternetOpen",
        "CryptDecrypt",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
    )
    hits = [i for i in imports if any(k.lower() in i.lower() for k in suspicious_keywords)]
    if hits:
        findings.append(
            Finding(
                engine="structure",
                severity="medium",
                title="APIs de interesse (injecção/rede/anti-debug/crypto)",
                detail="; ".join(hits[:40]),
                confidence=0.8,
            )
        )

    return {
        "format": "PE32+" if is_64 else "PE32",
        "entry_point": hex(entry),
        "image_base": hex(image_base),
        "imports": imports,
        "exports": exports,
        "sections": sections,
        "findings": findings,
        "machine": machine,
        "is_64": is_64,
    }


def _parse_elf_basic(data: bytes) -> dict[str, Any] | None:
    if not data.startswith(b"\x7fELF") or len(data) < 52:
        return None
    ei_class = data[4]  # 1=32, 2=64
    ei_data = data[5]  # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"
    findings = [
        Finding(
            engine="structure",
            severity="info",
            title="ELF detectado",
            detail=f"class={'64' if ei_class == 2 else '32'} endian={'LE' if ei_data == 1 else 'BE'}",
            confidence=0.9,
        )
    ]
    if ei_class == 1:
        e_entry = struct.unpack_from(endian + "I", data, 24)[0]
        e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
        e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
    else:
        e_entry = struct.unpack_from(endian + "Q", data, 24)[0]
        e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]

    return {
        "format": "ELF64" if ei_class == 2 else "ELF32",
        "entry_point": hex(e_entry),
        "image_base": "n/a",
        "imports": [],
        "exports": [],
        "sections": [
            {"name": "phoff", "va": hex(e_phoff), "vsize": 0, "raw_size": 0, "entropy": 0, "chars": "0x0"},
            {"name": "shoff", "va": hex(e_shoff), "vsize": 0, "raw_size": 0, "entropy": 0, "chars": "0x0"},
        ],
        "findings": findings,
        "machine": 0,
        "is_64": ei_class == 2,
    }


def run_structure(data: bytes) -> dict[str, Any]:
    if data.startswith(b"MZ"):
        pe = _try_pefile(data)
        if pe:
            return pe
        return {
            "format": "PE(incomplete)",
            "entry_point": "",
            "image_base": "",
            "imports": [],
            "exports": [],
            "sections": [],
            "findings": [
                Finding(
                    engine="structure",
                    severity="medium",
                    title="PE detectado mas pefile indisponível/falhou",
                    detail="Instale pefile: pip install pefile",
                    confidence=0.5,
                )
            ],
            "machine": 0,
            "is_64": False,
        }

    elf = _parse_elf_basic(data)
    if elf:
        return elf

    return {
        "format": "raw/unknown",
        "entry_point": "",
        "image_base": "",
        "imports": [],
        "exports": [],
        "sections": [],
        "findings": [
            Finding(
                engine="structure",
                severity="info",
                title="Sem PE/ELF reconhecido",
                detail="Análise estrutural limitada a bytes brutos.",
                confidence=0.9,
            )
        ],
        "machine": 0,
        "is_64": False,
    }
