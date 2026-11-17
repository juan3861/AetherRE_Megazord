"""Reverse Engineering Graph (AetherRE) — Sliding-Window Entropy & Compiler/Packer Detector.

Heurísticas na linha de Detect-It-Easy / PyPackerDetect / PEiD (reimplementadas;
nenhum código ou banco de assinaturas desses projetos foi copiado):
  1. Entropia de Shannon em janela deslizante com histograma incremental
     (O(N) em vez de O(N·W/step));
  2. Assinaturas de compilador (strings marcadoras);
  3. Assinaturas de packers/protetores por nome de seção e por bytes;
  4. Heurística genérica de packing por fração de bytes de alta entropia.

Limitação: assinaturas por string/seção são evidência fraca e facilmente
forjáveis; o resultado é indício, não prova de proveniência.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from aether_re.engines import pe_elf

SCHEMA = "packer-entropy-report.v1"

COMPILER_SIGNATURES: list[dict[str, Any]] = [
    {"compiler": ".NET (C#/F#/VB)", "markers": [b"mscoree.dll", b"_CorExeMain", b"System.Runtime"], "min": 2, "confidence": 0.95},
    {"compiler": "Go", "markers": [b"go.buildid", b"runtime.main", b"runtime.gopanic"], "min": 2, "confidence": 0.95},
    {"compiler": "Rust", "markers": [b"rust_begin_unwind", b"/rustc/", b"core::panicking"], "min": 1, "confidence": 0.90},
    {"compiler": "Borland Delphi / FreePascal", "markers": [b"Borland", b"Embarcadero", b"FPC "], "min": 1, "confidence": 0.85},
    {"compiler": "GCC / MinGW", "markers": [b"GCC: (", b"mingw", b"libgcc"], "min": 1, "confidence": 0.85},
    {"compiler": "Clang / LLVM", "markers": [b"clang version"], "min": 1, "confidence": 0.85},
    {"compiler": "Microsoft Visual C/C++", "markers": [b"VCRUNTIME", b"MSVCR", b"MSVCP", b"api-ms-win-crt-", b"RSDS"], "min": 1, "confidence": 0.75},
]

PACKER_SIGNATURES: list[dict[str, Any]] = [
    {"packer": "UPX", "sections": {"UPX0", "UPX1", "UPX2", ".UPX0", ".UPX1"}, "bytes": [b"UPX!"], "confidence": 0.99},
    {"packer": "ASPack", "sections": {".aspack", ".adata"}, "bytes": [b"ASPack"], "confidence": 0.95},
    {"packer": "VMProtect", "sections": {".vmp0", ".vmp1", ".vmp2"}, "bytes": [], "confidence": 0.95},
    {"packer": "Themida / WinLicense", "sections": {".themida", ".winlice"}, "bytes": [], "confidence": 0.95},
    {"packer": "MPRESS", "sections": {".MPRESS1", ".MPRESS2"}, "bytes": [], "confidence": 0.95},
    {"packer": "Enigma Protector", "sections": {".enigma1", ".enigma2"}, "bytes": [], "confidence": 0.95},
    {"packer": "PyInstaller", "sections": set(), "bytes": [b"MEI\x0c\x0b\x0a\x0b\x0e", b"_MEIPASS"], "confidence": 0.95},
    {"packer": "Nullsoft Installer (NSIS)", "sections": {".ndata"}, "bytes": [b"Nullsoft.NSIS"], "confidence": 0.95},
    {"packer": "Inno Setup", "sections": set(), "bytes": [b"Inno Setup Setup Data"], "confidence": 0.95},
]


def sliding_window_entropy(data: bytes, *, window_size: int = 512, step_size: int = 128, threshold: float = 7.2, max_blocks: int = 200) -> list[dict[str, Any]]:
    """Entropia de Shannon em janela deslizante com histograma incremental; agrega blocos contíguos >= threshold."""
    n = len(data)
    if window_size <= 0 or step_size <= 0 or n < window_size:
        return []
    hist = [0] * 256
    for b in data[:window_size]:
        hist[b] += 1
    # tabela c*log2(c) para c em [0, window]: H = log2(W) - sum(c log2 c)/W
    clog = [0.0] + [c * math.log2(c) for c in range(1, window_size + 1)]
    acc = sum(clog[c] for c in hist)
    log_w = math.log2(window_size)

    blocks: list[dict[str, Any]] = []
    start = None
    peak = total = 0.0
    pts = 0
    offset = 0
    last_end = 0
    while True:
        ent = log_w - acc / window_size
        if ent >= threshold:
            if start is None:
                start, peak, total, pts = offset, ent, ent, 1
            else:
                peak, total, pts = max(peak, ent), total + ent, pts + 1
            last_end = offset + window_size
        elif start is not None:
            blocks.append({"offset_hex": hex(start), "offset_dec": start, "length_bytes": last_end - start, "peak_entropy": round(peak, 4), "mean_entropy": round(total / pts, 4)})
            start = None
            if len(blocks) >= max_blocks:
                return blocks
        nxt = offset + step_size
        if nxt + window_size > n:
            break
        for b in data[offset:nxt]:
            c = hist[b]
            acc += clog[c - 1] - clog[c]
            hist[b] = c - 1
        for b in data[offset + window_size:nxt + window_size]:
            c = hist[b]
            acc += clog[c + 1] - clog[c]
            hist[b] = c + 1
        offset = nxt
    if start is not None and len(blocks) < max_blocks:
        blocks.append({"offset_hex": hex(start), "offset_dec": start, "length_bytes": last_end - start, "peak_entropy": round(peak, 4), "mean_entropy": round(total / pts, 4)})
    return blocks


def analyze_packer_and_compiler(target_path: Path | str, *, data: bytes | None = None) -> dict[str, Any]:
    p = Path(target_path)
    if data is None:
        if not p.is_file():
            raise FileNotFoundError(f"Arquivo alvo não encontrado: {target_path}")
        data = p.read_bytes()
    raw = data
    struct_info = pe_elf.run_structure(raw)
    section_names = {str(s.get("name", "")).strip("\x00 ").strip() for s in struct_info.get("sections", [])}
    lowered = raw.lower()

    compiler = {"name": "Unknown", "confidence": 0.0, "matched_signatures": []}
    for rule in COMPILER_SIGNATURES:
        hits = [m.decode("latin-1") for m in rule["markers"] if m.lower() in lowered]
        if len(hits) >= rule["min"]:
            compiler = {"name": rule["compiler"], "confidence": rule["confidence"], "matched_signatures": hits}
            break

    packer = {"name": "None Detected (Plain/Native)", "confidence": 0.0, "matched_signatures": []}
    detected = False
    for rule in PACKER_SIGNATURES:
        sec_hits = sorted(section_names & rule["sections"])
        byte_hits = [b.decode("latin-1") for b in rule["bytes"] if b in raw]
        if sec_hits or byte_hits:
            packer = {"name": rule["packer"], "confidence": rule["confidence"], "matched_signatures": sec_hits + byte_hits}
            detected = True
            break

    blocks = sliding_window_entropy(raw)
    high_bytes = sum(b["length_bytes"] for b in blocks)
    high_ratio = round(high_bytes / len(raw), 4) if raw else 0.0
    if not detected and high_bytes >= 4096 and high_ratio > 0.50:
        packer = {"name": "Generic High-Entropy Packer / Encrypted Payload", "confidence": 0.70, "matched_signatures": [f"high_entropy_ratio={high_ratio}"]}
        detected = True

    return {
        "schema": SCHEMA,
        "target": str(p),
        "file_size": len(raw),
        "is_packed": detected,
        "compiler": compiler,
        "packer": packer,
        "sliding_entropy": {
            "window_size": 512,
            "step_size": 128,
            "threshold": 7.2,
            "high_entropy_ratio": high_ratio,
            "high_entropy_blocks_count": len(blocks),
            "high_entropy_blocks": blocks[:20],
        },
        "limitations": ["assinaturas por string/seção são indícios forjáveis, não prova de proveniência"],
    }
