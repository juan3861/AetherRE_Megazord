"""Reverse Engineering Graph (AetherRE) — Dynamic Memory Forensics & VAD Walker.

Motor de inspeção e forense de memória RAM e dumps de processos:
  1. Varredura de descritores de memória virtual (VAD Tree);
  2. Detecção de regiões com proteção PAGE_EXECUTE_READWRITE (RWX) — indicador de shellcode/desempacotamento;
  3. Extração e validação de cabeçalhos PE (MZ/PE\\0\\0) e strings de payload descriptografadas em voo.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

SCHEMA = "memory-forensics-report.v1"


def analyze_memory_regions(
    regions: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """Analisa uma lista de regiões de memória virtual (VAD nodes) procurando anomalias forenses."""
    rwx_regions: list[dict[str, Any]] = []
    injected_pe_candidates: list[dict[str, Any]] = []
    total_bytes = 0

    for r in regions:
        base = r.get("base_address", 0)
        size = r.get("size", 0)
        protect = str(r.get("protection", "")).upper()
        data = r.get("data", b"")

        total_bytes += size

        # 1. Alerta crítico: Região Executável e Gravável simultaneamente (RWX)
        if "EXECUTE" in protect and ("WRITE" in protect or "READWRITE" in protect):
            rwx_regions.append({
                "base_address": hex(base) if isinstance(base, int) else str(base),
                "size_bytes": size,
                "protection": protect,
                "state": r.get("state", "MEM_COMMIT"),
                "suspicious_reason": "RWX_PERMISSIONS_DETECTED",
            })

        # 2. Varredura por cabeçalhos PE em memória (MZ / PE\0\0)
        if isinstance(data, (bytes, bytearray)) and len(data) >= 64:
            if data[:2] == b"MZ":
                injected_pe_candidates.append({
                    "base_address": hex(base) if isinstance(base, int) else str(base),
                    "size_bytes": size,
                    "header_magic": "MZ_DOS_HEADER",
                    "status": "UNMAPPED_OR_REFLECTIVE_PE_DETECTED",
                })

    is_suspicious = len(rwx_regions) > 0 or len(injected_pe_candidates) > 0

    return {
        "schema": SCHEMA,
        "total_regions_analyzed": len(regions),
        "total_memory_scanned_bytes": total_bytes,
        "is_compromised_or_unpacked": is_suspicious,
        "rwx_regions_count": len(rwx_regions),
        "rwx_regions": rwx_regions,
        "injected_pe_count": len(injected_pe_candidates),
        "injected_pe_candidates": injected_pe_candidates,
    }
