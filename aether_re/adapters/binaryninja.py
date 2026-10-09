"""Adapter Binary Ninja — decompilação e análise via API Binary Ninja (opcional)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from aether_re.adapters.base import Adapter


class BinaryNinjaAdapter(Adapter):
    """Adapter para Binary Ninja (requer licença válida).

    Este adapter é um placeholder — a funcionalidade completa requer:
    1. Licença Binary Ninja válida
    2. Instalação do Binary Ninja
    3. A API Python (binaryninja) disponível no ambiente

    Quando disponível, contribui com:
    - Decompilação IL de alta qualidade (MLIL/HLIL)
    - Análise de fluxo de dados
    - Type inference e recovery de assinaturas
    """

    name = "binaryninja"

    def available(self) -> bool:
        try:
            import binaryninja  # noqa: F401

            return True
        except ImportError:
            return False

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        if not self.available():
            return {
                "ok": False,
                "available": False,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "Binary Ninja não disponível (requer licença e API Python)",
                "hint": "Instale Binary Ninja e adicione a API ao PYTHONPATH",
            }

        try:
            import binaryninja
        except Exception as e:
            return {
                "ok": False,
                "executed": False,
                "produced_evidence": False,
                "error": f"Erro ao importar Binary Ninja API: {e}",
            }

        try:
            # Carregar o binário com análise profunda
            bv = binaryninja.load(str(target))
            if bv is None:
                return {
                    "ok": False,
                    "executed": True,
                    "produced_evidence": False,
                    "error": "Binary Ninja não pôde carregar o arquivo",
                }

            # Executar análise completa
            bv.update_analysis_and_wait()

            functions = []
            for func in bv.functions:
                # Obter decompilação MLIL (pseudo-C)
                mlil = func.mlil
                pseudocode = str(mlil) if mlil else ""

                # Obter chamadas
                calls = []
                for block in func.basic_blocks:
                    for insn in block:
                        if insn.operation == binaryninja.MediumLevelILOperation.MLIL_CALL:
                            if insn.dest.operation == binaryninja.MediumLevelILOperation.MLIL_CONST_PTR:
                                calls.append(f"0x{insn.dest.constant:x}")

                # Imports usados
                imports_used = []
                for sym in func.imported_symbols:
                    imports_used.append(f"{sym.type.name}!{sym.name}")

                # Strings próximas
                strings_near = []
                for ref in func.string_references:
                    s = str(ref.string)[:120]
                    if s:
                        strings_near.append(s)

                functions.append({
                    "address": f"0x{func.start:x}",
                    "name": func.name,
                    "source": "binaryninja",
                    "confidence": 0.92,
                    "quality": 0.90,
                    "coverage": 1.0,
                    "pseudocode": pseudocode,
                    "calls": calls[:50],
                    "imports_used": imports_used[:20],
                    "strings_near": strings_near[:20],
                    "notes": "Binary Ninja MLIL decompilation",
                    "warnings": [],
                    "raw": {
                        "blocks": len(list(func.basic_blocks)),
                        "has_hlil": func.hlil is not None,
                        "has_mlil": func.mlil is not None,
                    }
                })

            report_path = out_dir / "binaryninja_report.json"
            import json
            report_path.write_text(json.dumps({
                "ok": True,
                "executed": True,
                "produced_evidence": True,
                "functions": functions,
                "arch": str(bv.arch),
                "entry": f"0x{bv.entry_point:x}" if bv.entry_point else "0x0",
            }, indent=2, default=str), encoding="utf-8")

            return {
                "ok": True,
                "executed": True,
                "produced_evidence": True,
                "partial": False,
                "functions": functions,
                "arch": str(bv.arch),
                "entry": f"0x{bv.entry_point:x}" if bv.entry_point else "0x0",
                "report": str(report_path),
            }

        except Exception as e:
            return {
                "ok": False,
                "executed": True,
                "produced_evidence": False,
                "error": f"Binary Ninja analysis failed: {e}",
            }
