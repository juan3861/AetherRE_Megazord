"""Motor STRUCTURE — PE (estilo Ghidra/Cutter triage) e ELF básico."""

from __future__ import annotations

import math
import struct
from typing import Any

from aether_re.models import Finding


def _try_pefile(data: bytes) -> dict[str, Any] | None:
    try:
        import pefile  # type: ignore
    except ImportError:
        return None

    try:
        pe = pefile.PE(data=data, fast_load=False)
        pe.parse_data_directories()
    except Exception as exc:  # pefile raises format-specific exceptions for truncated input
        return {
            "format": "PE(invalid)",
            "entry_point": "",
            "image_base": "",
            "image_base_kind": "unknown",
            "imports": [],
            "exports": [],
            "needed_libraries": [],
            "symbols": [],
            "relocations": [],
            "segments": [],
            "sections": [],
            "findings": [
                Finding(
                    engine="structure",
                    severity="medium",
                    title="PE inválido/truncado",
                    detail=f"{type(exc).__name__}: {str(exc)[:240]}",
                    confidence=0.6,
                )
            ],
            "machine": 0,
            "is_64": False,
        }

    imports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for import_entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = import_entry.dll.decode(errors="ignore") if import_entry.dll else "?"
            for imp in import_entry.imports:
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
    segments: list[dict[str, Any]] = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="ignore")
        chars = int(s.Characteristics)
        permissions = "".join(
            label
            for bit, label in (
                (0x40000000, "R"),
                (0x80000000, "W"),
                (0x20000000, "X"),
            )
            if chars & bit
        ) or "-"
        raw_offset = int(s.PointerToRawData)
        raw_size = int(s.SizeOfRawData)
        payload_ok = raw_offset <= len(data) and raw_size <= len(data) - raw_offset
        payload = data[raw_offset:raw_offset + raw_size] if payload_ok else b""
        section = {
            "index": len(sections),
            "name": name,
            "va": hex(int(s.VirtualAddress)),
            "offset": raw_offset,
            "vsize": int(s.Misc_VirtualSize),
            "raw_size": raw_size,
            "entropy": round(_entropy(payload), 4),
            "chars": hex(chars),
            "permissions": permissions,
        }
        sections.append(section)
        segments.append(
            {
                "index": len(segments),
                "type": "section",
                "type_name": "SECTION",
                "offset": raw_offset,
                "vaddr": hex(int(s.VirtualAddress)),
                "filesz": raw_size,
                "memsz": int(s.Misc_VirtualSize),
                "flags": chars,
                "permissions": permissions,
                "raw_size": len(payload),
                "entropy": round(_entropy(payload), 4),
            }
        )

    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase
    machine = pe.FILE_HEADER.Machine
    is_64 = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS

    needed_libraries = sorted(
        {
            item.split("!", 1)[0]
            for item in imports
            if "!" in item and item.split("!", 1)[0]
        }
    )
    symbols: list[dict[str, Any]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode(errors="ignore") if exp.name else f"ord_{exp.ordinal}"
            symbols.append(
                {
                    "name": name,
                    "value": hex(int(exp.address)),
                    "rva": hex(int(exp.address)),
                    "address_space": "preferred_rva",
                    "value_kind": "rva",
                    "kind": "export",
                    "ordinal": int(exp.ordinal),
                    "source": "pe-export",
                }
            )
    relocations: list[dict[str, Any]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC") and pe.DIRECTORY_ENTRY_BASERELOC:
        for block in pe.DIRECTORY_ENTRY_BASERELOC:
            page_rva = int(block.struct.VirtualAddress)
            for reloc_entry in block.entries:
                relocations.append(
                    {
                        "rva": hex(int(reloc_entry.rva)),
                        "offset": hex(int(reloc_entry.rva)),
                        "type": int(reloc_entry.type),
                        "page_rva": hex(page_rva),
                        "symbol": "",
                    }
                )

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
        if int(s["chars"], 16) & 0x20000000
        and int(s["chars"], 16) & 0x80000000
    ]
    malformed_sections = [
        s for s in sections if s["offset"] > len(data) or s["raw_size"] > len(data) - s["offset"]
    ]
    if malformed_sections:
        findings.append(
            Finding(
                engine="structure",
                severity="medium",
                title="Seção PE fora do artefato",
                detail=", ".join(s["name"] or f"section_{s['index']}" for s in malformed_sections[:20]),
                confidence=0.7,
            )
        )
    section_ranges = sorted(
        (section["offset"], section["offset"] + section["raw_size"], section["index"])
        for section in sections
        if section["raw_size"] and section["offset"] < len(data)
    )
    for previous, current in zip(section_ranges, section_ranges[1:]):
        if current[0] < previous[1]:
            findings.append(
                Finding(
                    engine="structure",
                    severity="medium",
                    title="Seções PE sobrepostas",
                    detail=(
                        f"index={previous[2]} range=0x{previous[0]:X}-0x{previous[1]:X}; "
                        f"index={current[2]} range=0x{current[0]:X}-0x{current[1]:X}"
                    ),
                    confidence=0.7,
                )
            )
    if exec_rw:
        findings.append(
            Finding(
                engine="structure",
                severity="medium",
                title="Seção PE gravável e executável",
                detail=", ".join(s["name"] or f"section_{s['index']}" for s in exec_rw),
                confidence=0.7,
            )
        )
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
        "image_base_kind": "preferred_vaddr",
        "imports": imports,
        "exports": exports,
        "needed_libraries": needed_libraries,
        "symbols": symbols,
        "relocations": relocations,
        "segments": segments,
        "sections": sections,
        "findings": findings,
        "machine": machine,
        "is_64": is_64,
        "endianness": "little",
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    size = len(data)
    entropy = round(-sum((count / size) * math.log2(count / size) for count in counts if count), 4)
    return 0.0 if entropy == 0.0 else entropy


def _parse_elf_basic(data: bytes) -> dict[str, Any] | None:
    """Parse ELF metadata without executing or trusting the target.

    This is deliberately a bounded structural reader.  It reports malformed
    tables instead of guessing, and keeps sections, segments, symbols and
    relocations separate so later correlation can attach its own provenance.
    """
    if not data.startswith(b"\x7fELF"):
        return None

    def empty_result(fmt: str, *, is_64: bool = False, detail: str = "", severity: str = "medium", confidence: float = 0.5) -> dict[str, Any]:
        return {
            "format": fmt,
            "entry_point": "",
            "image_base": "n/a",
            "image_base_kind": "unknown",
            "imports": [],
            "exports": [],
            "needed_libraries": [],
            "symbols": [],
            "relocations": [],
            "segments": [],
            "sections": [],
            "findings": [Finding(engine="structure", severity=severity, title="ELF estrutural", detail=detail, confidence=confidence)],
            "machine": 0,
            "machine_name": "unknown",
            "is_64": is_64,
        }

    if len(data) < 52:
        return empty_result("ELF(truncated)", detail=f"bytes={len(data)} required=52")
    ei_class = data[4]  # 1=32, 2=64
    ei_data = data[5]  # 1=little-endian, 2=big-endian
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return empty_result("ELF(invalid-header)", detail=f"class={ei_class} data={ei_data}", confidence=0.4)
    minimum = 64 if ei_class == 2 else 52
    if len(data) < minimum:
        return empty_result("ELF(truncated)", is_64=ei_class == 2, detail=f"bytes={len(data)} required={minimum}")

    endian = "<" if ei_data == 1 else ">"
    try:
        e_type, e_machine, e_version = struct.unpack_from(endian + "HHI", data, 16)
        if ei_class == 1:
            e_entry, e_phoff, e_shoff, e_flags = struct.unpack_from(endian + "IIII", data, 24)
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHHHHH", data, 40)
            ph_fmt, ph_size = "IIIIIIII", 32
            section_fmt, section_size = "IIIIIIIIII", 40
            symbol_fmt, symbol_size = "IIIBBH", 16
        else:
            e_entry, e_phoff, e_shoff = struct.unpack_from(endian + "QQQ", data, 24)
            e_flags = struct.unpack_from(endian + "I", data, 48)[0]
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHHHHH", data, 52)
            ph_fmt, ph_size = "IIQQQQQQ", 56
            section_fmt, section_size = "IIQQQQIIQQ", 64
            symbol_fmt, symbol_size = "IBBHQQ", 24
    except struct.error:
        return empty_result("ELF(truncated)", is_64=ei_class == 2, detail="campos estruturais incompletos", confidence=0.4)

    machine_names = {3: "i386", 8: "mips", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
    type_names = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
    section_type_names = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY"}
    segment_type_names = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB", 6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO"}
    extended_numbering = False

    # ELF uses sentinel values for large tables.  Resolve them from section 0
    # when the table is safely addressable; otherwise retain an explicit
    # malformed status rather than iterating an attacker-controlled count.
    section0_values: tuple[Any, ...] | None = None
    if e_shoff > 0 and e_shentsize >= section_size and e_shoff <= len(data) and e_shoff + section_size <= len(data):
        try:
            section0_values = struct.unpack_from(endian + section_fmt, data, e_shoff)
        except struct.error:
            section0_values = None
    if section0_values is not None:
        if e_shnum == 0 and e_shoff:
            extended_count = int(section0_values[5])
            if 0 < extended_count <= 1_000_000:
                e_shnum = extended_count
                extended_numbering = True
        if e_shstrndx == 0xFFFF:
            extended_index = int(section0_values[6])
            if extended_index <= 1_000_000:
                e_shstrndx = extended_index
                extended_numbering = True
        if e_phnum == 0xFFFF:
            extended_phnum = int(section0_values[7])
            if extended_phnum <= 1_000_000:
                e_phnum = extended_phnum
                extended_numbering = True
    findings = [Finding(engine="structure", severity="info", title="ELF detectado", detail=f"class={'64' if ei_class == 2 else '32'} endian={'LE' if ei_data == 1 else 'BE'} type={type_names.get(e_type, hex(e_type))} machine=0x{e_machine:X} entry={hex(e_entry)}", confidence=0.9)]
    if e_ehsize < minimum:
        findings.append(Finding(engine="structure", severity="medium", title="Tamanho de cabeçalho ELF inconsistente", detail=f"ehsize={e_ehsize} required>={minimum}", confidence=0.6))
    if e_version != 1:
        findings.append(Finding(engine="structure", severity="medium", title="Versão ELF não suportada", detail=f"version={e_version} expected=1", confidence=0.6))

    def cstring(blob: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(blob):
            return ""
        end = blob.find(b"\x00", offset)
        return blob[offset:end if end >= 0 else len(blob)].decode("utf-8", errors="replace")

    # Program headers / load segments.
    segments_raw: list[dict[str, Any]] = []
    valid_ph = e_phnum == 0 and e_phoff == 0
    if e_phnum:
        table_end = e_phoff + e_phentsize * e_phnum
        if e_phoff > 0 and e_phentsize >= ph_size and e_phoff <= len(data) and table_end <= len(data):
            valid_ph = True
            for index in range(e_phnum):
                offset = e_phoff + index * e_phentsize
                try:
                    values = struct.unpack_from(endian + ph_fmt, data, offset)
                except struct.error:
                    valid_ph = False
                    break
                if ei_class == 1:
                    p_type, file_off, vaddr, paddr, filesz, memsz, flags, align = values
                else:
                    p_type, flags, file_off, vaddr, paddr, filesz, memsz, align = values
                payload_ok = file_off <= len(data) and filesz <= len(data) - file_off
                payload = data[file_off:file_off + filesz] if payload_ok else b""
                flag_text = "".join(name for bit, name in ((4, "R"), (2, "W"), (1, "X")) if flags & bit) or "-"
                segments_raw.append({"index": index, "type": p_type, "type_name": segment_type_names.get(p_type, hex(p_type)), "offset": file_off, "vaddr": hex(vaddr), "paddr": hex(paddr), "filesz": filesz, "memsz": memsz, "flags": flags, "permissions": flag_text, "align": align, "raw_size": len(payload), "entropy": _entropy(payload)})
                if not payload_ok:
                    findings.append(Finding(engine="structure", severity="medium", title="Segmento ELF fora do artefato", detail=f"index={index} offset={file_off} size={filesz} bytes={len(data)}", confidence=0.6))
                if flags & 0x2 and flags & 0x1:
                    findings.append(Finding(engine="structure", severity="medium", title="Segmento ELF gravável e executável", detail=f"index={index} permissions={flag_text}", confidence=0.7))
        else:
            valid_ph = False
    if not valid_ph:
        findings.append(Finding(engine="structure", severity="medium", title="Tabela ELF de segmentos inválida/truncada", detail="offset/count/entry-size excede o artefato", confidence=0.5))

    # Section headers.  A non-zero count must never be read from offset zero.
    sections_raw: list[dict[str, Any]] = []
    valid_sh = e_shnum == 0 and e_shoff == 0
    if e_shnum:
        table_end = e_shoff + e_shentsize * e_shnum
        if e_shoff > 0 and e_shentsize >= section_size and e_shoff <= len(data) and table_end <= len(data):
            valid_sh = True
            for index in range(e_shnum):
                offset = e_shoff + index * e_shentsize
                try:
                    values = struct.unpack_from(endian + section_fmt, data, offset)
                except struct.error:
                    valid_sh = False
                    break
                name_off, sh_type, flags, addr, file_off, size, link, info, align, entsize = values
                payload_ok = sh_type == 8 or (file_off <= len(data) and size <= len(data) - file_off)
                payload = b"" if sh_type == 8 or not payload_ok else data[file_off:file_off + size]
                sections_raw.append({"index": index, "name_off": name_off, "type": sh_type, "flags": flags, "addr": addr, "offset": file_off, "size": size, "link": link, "info": info, "align": align, "entsize": entsize, "payload": payload})
                if not payload_ok:
                    findings.append(Finding(engine="structure", severity="medium", title="Seção ELF fora do artefato", detail=f"index={index} offset={file_off} size={size} bytes={len(data)}", confidence=0.6))
        else:
            valid_sh = False
    elif e_shoff:
        valid_sh = False
    if not valid_sh:
        findings.append(Finding(engine="structure", severity="medium", title="Tabela ELF de seções inválida/truncada", detail="offset/count/entry-size excede o artefato", confidence=0.5))

    names_blob = sections_raw[e_shstrndx]["payload"] if 0 <= e_shstrndx < len(sections_raw) else b""
    sections = [{"name": cstring(names_blob, item["name_off"]) or f"section_{item['index']}", "type": item["type"], "type_name": section_type_names.get(item["type"], hex(item["type"])), "va": hex(item["addr"]), "offset": item["offset"], "vsize": item["size"], "raw_size": len(item["payload"]), "entropy": _entropy(item["payload"]), "chars": hex(item["flags"])} for item in sections_raw]
    file_ranges = sorted((item["offset"], item["offset"] + item["size"], item["index"]) for item in sections_raw if item["type"] != 8 and item["size"] and item["offset"] < len(data))
    for previous, current in zip(file_ranges, file_ranges[1:]):
        if current[0] < previous[1]:
            findings.append(Finding(engine="structure", severity="medium", title="Seções ELF sobrepostas", detail=f"index={previous[2]} range=0x{previous[0]:X}-0x{previous[1]:X}; index={current[2]} range=0x{current[0]:X}-0x{current[1]:X}", confidence=0.6))

    # Symbol tables and dynamic dependencies.
    imports: list[str] = []
    exports: list[str] = []
    symbols: list[dict[str, Any]] = []
    symbols_by_section: dict[int, list[dict[str, Any]]] = {}
    needed_libraries: list[str] = []

    def vaddr_to_file(vaddr: int) -> int | None:
        for segment in segments_raw:
            if segment["type"] != 1:
                continue
            base = int(segment["vaddr"], 16)
            offset = int(segment["offset"])
            filesz = int(segment["filesz"])
            if base <= vaddr < base + filesz:
                return offset + (vaddr - base)
        return None
    for item in sections_raw:
        if item["type"] not in (2, 11) or item["link"] >= len(sections_raw):
            continue
        entsize = item["entsize"] or symbol_size
        if entsize < symbol_size:
            findings.append(Finding(engine="structure", severity="medium", title="Tabela de símbolos ELF inválida", detail=f"section={item['index']} entsize={entsize}", confidence=0.5))
            continue
        strtab = sections_raw[item["link"]]["payload"]
        table_symbols: list[dict[str, Any]] = []
        for index in range(0, len(item["payload"]) // entsize):
            offset = index * entsize
            try:
                values = struct.unpack_from(endian + symbol_fmt, item["payload"], offset)
            except struct.error:
                table_symbols.append({})
                continue
            if ei_class == 1:
                name_off, value, size, info_byte, other, shndx = values
            else:
                name_off, info_byte, other, shndx, value, size = values
            name = cstring(strtab, name_off)
            if not name:
                # Preserve table indexes (the null symbol is index zero).
                table_symbols.append({})
                continue
            bind, symbol_type = info_byte >> 4, info_byte & 0xF
            record = {
                "table": item["index"],
                "index": index,
                "name": name,
                "value": hex(value),
                "rva": "",
                "address_space": "preferred_vaddr",
                "value_kind": "virtual_address",
                "size": size,
                "bind": bind,
                "type": symbol_type,
                "visibility": other & 0x3,
                "section_index": shndx,
            }
            table_symbols.append(record)
            symbols.append(record)
            if shndx == 0:
                imports.append(name)
            elif bind in (1, 2) and (other & 0x3) not in (2, 3):
                exports.append(name)
        symbols_by_section[item["index"]] = table_symbols

    for item in sections_raw:
        if item["type"] != 6 or item["link"] >= len(sections_raw):
            continue
        entsize = item["entsize"] or (8 if ei_class == 1 else 16)
        if entsize < (8 if ei_class == 1 else 16):
            continue
        strtab = sections_raw[item["link"]]["payload"]
        for offset in range(0, len(item["payload"]) - entsize + 1, entsize):
            try:
                tag, value = struct.unpack_from(endian + ("II" if ei_class == 1 else "QQ"), item["payload"], offset)
            except struct.error:
                break
            if tag == 1:
                name = cstring(strtab, value)
                if name:
                    needed_libraries.append(name)

    # Stripped ELF files may retain PT_DYNAMIC while omitting section headers.
    # Recover DT_NEEDED from the loadable image without inventing symbols.
    dynamic_needed_offsets: list[int] = []
    dynamic_strtab_vaddr: int | None = None
    dynamic_strtab_size: int | None = None
    dynamic_entry_size = 8 if ei_class == 1 else 16
    dynamic_unpack = "II" if ei_class == 1 else "QQ"
    for segment in segments_raw:
        if segment["type"] != 2 or int(segment["filesz"]) < dynamic_entry_size:
            continue
        segment_offset = int(segment["offset"])
        segment_size = int(segment["filesz"])
        if segment_offset > len(data) or segment_size > len(data) - segment_offset:
            continue
        payload = data[segment_offset:segment_offset + segment_size]
        for offset in range(0, len(payload) - dynamic_entry_size + 1, dynamic_entry_size):
            try:
                tag, value = struct.unpack_from(endian + dynamic_unpack, payload, offset)
            except struct.error:
                break
            if tag == 0:
                break
            if tag == 1:
                dynamic_needed_offsets.append(value)
            elif tag == 5:
                dynamic_strtab_vaddr = value
            elif tag == 10:
                dynamic_strtab_size = value
    if dynamic_needed_offsets and dynamic_strtab_vaddr is not None:
        strtab_offset = vaddr_to_file(dynamic_strtab_vaddr)
        if strtab_offset is not None and strtab_offset <= len(data):
            available = len(data) - strtab_offset
            strtab = data[strtab_offset:strtab_offset + min(dynamic_strtab_size or available, available)]
            for name_offset in dynamic_needed_offsets:
                name = cstring(strtab, name_offset)
                if name:
                    needed_libraries.append(name)

    # REL/RELA entries retain offsets and referenced symbol names for later correlation.
    relocations: list[dict[str, Any]] = []
    for item in sections_raw:
        if item["type"] not in (4, 9):
            continue
        entry_size = (12 if ei_class == 1 else 24) if item["type"] == 4 else (8 if ei_class == 1 else 16)
        entsize = item["entsize"] or entry_size
        if entsize < entry_size:
            continue
        table = symbols_by_section.get(item["link"], [])
        for offset in range(0, len(item["payload"]) - entsize + 1, entsize):
            try:
                if ei_class == 1:
                    if item["type"] == 4:
                        r_offset, r_info, addend = struct.unpack_from(endian + "IIi", item["payload"], offset)
                    else:
                        r_offset, r_info = struct.unpack_from(endian + "II", item["payload"], offset)
                        addend = None
                    symbol_index, relocation_type = r_info >> 8, r_info & 0xFF
                else:
                    if item["type"] == 4:
                        r_offset, r_info, addend = struct.unpack_from(endian + "QQq", item["payload"], offset)
                    else:
                        r_offset, r_info = struct.unpack_from(endian + "QQ", item["payload"], offset)
                        addend = None
                    symbol_index, relocation_type = r_info >> 32, r_info & 0xFFFFFFFF
            except struct.error:
                continue
            symbol_name = table[symbol_index].get("name", "") if symbol_index < len(table) else ""
            relocations.append({"section": item["index"], "offset": hex(r_offset), "type": relocation_type, "symbol": symbol_name, "addend": addend})

    load_bases = [int(segment["vaddr"], 16) for segment in segments_raw if segment["type"] == 1]
    preferred_base = min(load_bases) if load_bases else None
    for symbol in symbols:
        value_text = symbol.get("value", "")
        try:
            value_int = int(str(value_text), 0)
        except (TypeError, ValueError):
            value_int = None
        if preferred_base is not None and value_int is not None and value_int >= preferred_base:
            symbol["rva"] = hex(value_int - preferred_base)
        else:
            symbol["rva"] = ""
    image_base = hex(preferred_base) if preferred_base is not None else "n/a"
    # For ET_DYN this is the preferred virtual base; the runtime load bias is
    # intentionally unknown until an external, authorized trace supplies it.
    image_base_kind = "preferred_vaddr" if load_bases else "unknown"
    findings[0].detail += f" segments={len(segments_raw)} sections={len(sections)} symbols={len(symbols)} imports={len(imports)} exports={len(exports)} relocations={len(relocations)}"
    visible_sections = sections or [{"name": "phoff", "va": hex(e_phoff), "vsize": 0, "raw_size": 0, "entropy": 0, "chars": "0x0"}, {"name": "shoff", "va": hex(e_shoff), "vsize": 0, "raw_size": 0, "entropy": 0, "chars": "0x0"}]
    return {"format": "ELF64" if ei_class == 2 else "ELF32", "entry_point": hex(e_entry), "image_base": image_base, "image_base_kind": image_base_kind, "imports": sorted(set(imports)), "exports": sorted(set(exports)), "needed_libraries": sorted(set(needed_libraries)), "symbols": symbols, "relocations": relocations, "segments": segments_raw, "sections": visible_sections, "findings": findings, "machine": e_machine, "machine_name": machine_names.get(e_machine, "unknown"), "is_64": ei_class == 2, "endianness": "little" if ei_data == 1 else "big", "type": e_type, "type_name": type_names.get(e_type, hex(e_type)), "version": e_version, "flags": e_flags, "header_size": e_ehsize, "extended_numbering": extended_numbering}


def run_structure(data: bytes) -> dict[str, Any]:
    if data.startswith(b"MZ"):
        pe = _try_pefile(data)
        if pe:
            return pe
        return {
            "format": "PE(incomplete)",
            "entry_point": "",
            "image_base": "",
            "image_base_kind": "unknown",
            "imports": [],
            "exports": [],
            "needed_libraries": [],
            "symbols": [],
            "relocations": [],
            "segments": [],
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
        "image_base_kind": "unknown",
        "imports": [],
        "exports": [],
        "needed_libraries": [],
        "symbols": [],
        "relocations": [],
        "segments": [],
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
