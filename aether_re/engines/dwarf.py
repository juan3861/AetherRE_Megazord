"""Leitura opcional e estática de informação DWARF em objetos ELF.

O módulo só consome bytes do artefato já capturado pelo pipeline.  Ele não
carrega o binário, não resolve símbolos no sistema e não executa código.
pyelftools é uma dependência opcional: sua ausência é um estado de capacidade,
nunca um sucesso vazio.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Any


SCHEMA = "dwarf-analysis.v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value) if value is not None else ""


def _empty(path: Path, *, status: str, detail: str, available: bool, severity: str = "info") -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "available": available,
        "executed": False,
        "produced_evidence": False,
        "target": str(path),
        "target_sha256": "",
        "functions": [],
        "compilation_units": [],
        "findings": [{"severity": severity, "title": "DWARF", "detail": detail}],
        "limitations": ["DWARF é evidência de debug do artefato, não prova de comportamento", "sem execução, loader ou validação fonte→binário", "informação pode estar ausente, incompleta ou adulterada"],
    }


def analyze_dwarf(path: Path, *, max_cus: int = 10_000, max_dies: int = 500_000) -> dict[str, Any]:
    """Extract bounded subprogram DIEs and CU metadata from an ELF file."""
    path = path.resolve()
    try:
        raw = path.read_bytes()
    except (FileNotFoundError, OSError) as exc:
        return _empty(path, status="invalid", detail=f"artefato ilegível: {type(exc).__name__}", available=False, severity="medium")
    if not raw.startswith(b"\x7fELF"):
        result = _empty(path, status="not_applicable", detail="artefato não é ELF", available=False)
        result["target_sha256"] = hashlib.sha256(raw).hexdigest()
        return result
    try:
        from elftools.dwarf.descriptions import describe_form_class
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        result = _empty(path, status="unavailable", detail=f"pyelftools indisponível: {type(exc).__name__}", available=False, severity="medium")
        result["target_sha256"] = hashlib.sha256(raw).hexdigest()
        return result
    try:
        elf = ELFFile(io.BytesIO(raw))
    except Exception as exc:  # pyelftools exposes several parser-specific errors
        result = _empty(path, status="invalid", detail=f"ELF/DWARF inválido: {type(exc).__name__}", available=True, severity="medium")
        result["target_sha256"] = hashlib.sha256(raw).hexdigest()
        return result
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "not_present",
        "available": True,
        "executed": False,
        "produced_evidence": False,
        "target": str(path),
        "target_sha256": _sha256(path),
        "functions": [],
        "compilation_units": [],
        "findings": [],
        "limitations": ["DWARF é evidência de debug do artefato, não prova de comportamento", "sem execução, loader ou validação fonte→binário", "informação pode estar ausente, incompleta ou adulterada"],
    }
    try:
        if not elf.has_dwarf_info():
            result["findings"].append({"severity": "info", "title": "DWARF ausente", "detail": "ELF não contém informação DWARF reconhecida"})
            return result
        dwarf = elf.get_dwarf_info()
        die_count = 0
        for cu_index, cu in enumerate(dwarf.iter_CUs()):
            if cu_index >= max_cus:
                result["status"] = "partial"
                result["findings"].append({"severity": "medium", "title": "Budget de compilation units atingido", "detail": f"max_cus={max_cus}"})
                break
            top = cu.get_top_DIE()
            cu_record = {"index": cu_index, "offset": cu.cu_offset, "length": cu['unit_length'], "producer": _text(top.attributes.get("DW_AT_producer", {}).value if top.attributes.get("DW_AT_producer") else ""), "language": _text(top.attributes.get("DW_AT_language", {}).value if top.attributes.get("DW_AT_language") else "")}
            result["compilation_units"].append(cu_record)
            for die in cu.iter_DIEs():
                die_count += 1
                if die_count > max_dies:
                    result["status"] = "partial"
                    result["findings"].append({"severity": "medium", "title": "Budget de DIEs atingido", "detail": f"max_dies={max_dies}"})
                    break
                if die.tag not in {"DW_TAG_subprogram", "DW_TAG_inlined_subroutine"}:
                    continue
                name_attr = die.attributes.get("DW_AT_linkage_name") or die.attributes.get("DW_AT_MIPS_linkage_name") or die.attributes.get("DW_AT_name")
                name = _text(name_attr.value if name_attr else "")
                if not name:
                    continue
                low_attr = die.attributes.get("DW_AT_low_pc")
                high_attr = die.attributes.get("DW_AT_high_pc")
                low = int(low_attr.value) if low_attr and isinstance(low_attr.value, int) else None
                high: int | None = None
                if high_attr and isinstance(high_attr.value, int):
                    form_class = describe_form_class(high_attr.form)
                    high = int(high_attr.value) if form_class == "address" else (low + int(high_attr.value) if low is not None and form_class == "constant" else None)
                result["functions"].append({"name": name, "die_offset": die.offset, "tag": die.tag, "low_pc": hex(low) if low is not None else None, "high_pc": hex(high) if high is not None else None, "decl_line": int(die.attributes["DW_AT_decl_line"].value) if "DW_AT_decl_line" in die.attributes and isinstance(die.attributes["DW_AT_decl_line"].value, int) else None, "decl_file_index": int(die.attributes["DW_AT_decl_file"].value) if "DW_AT_decl_file" in die.attributes and isinstance(die.attributes["DW_AT_decl_file"].value, int) else None, "compilation_unit": cu_index, "heuristic": False, "method": "DWARF_DIE"})
            if die_count > max_dies:
                break
    except Exception as exc:
        result["status"] = "partial" if result["functions"] or result["compilation_units"] else "invalid"
        result["findings"].append({"severity": "medium", "title": "Leitura DWARF interrompida", "detail": type(exc).__name__})
    if result["functions"] or result["compilation_units"]:
        result["produced_evidence"] = True
        if result["status"] == "not_present":
            result["status"] = "succeeded"
    elif result["status"] == "not_present":
        result["findings"].append({"severity": "info", "title": "DWARF sem unidades de compilação", "detail": "seções reconhecidas, mas nenhum CU foi encontrado"})
    return result
