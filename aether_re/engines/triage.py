"""Motor TRIAGE — hashes, entropy, magic bytes (estilo forense ImHex + malware labs)."""

from __future__ import annotations

import hashlib
import math
import struct
from collections import Counter
from pathlib import Path

from aether_re.models import Finding


MAGIC_MAP: list[tuple[bytes, str]] = [
    (b"MZ", "pe/dos"),
    (b"\x7fELF", "elf"),
    (b"\xca\xfe\xba\xbe", "mach-o-fat"),
    (b"\xcf\xfa\xed\xfe", "mach-o-64"),
    (b"\xce\xfa\xed\xfe", "mach-o-32"),
    (b"PK\x03\x04", "zip/jar/apk/docx"),
    (b"%PDF", "pdf"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"#!", "script"),
]


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def detect_magic(data: bytes) -> str:
    for sig, name in MAGIC_MAP:
        if data.startswith(sig):
            return name
    if len(data) >= 4:
        # WASM
        if data[:4] == b"\x00asm":
            return "wasm"
    return "unknown"


def sliding_entropy(data: bytes, window: int = 4096, step: int = 4096) -> list[dict]:
    out: list[dict] = []
    if not data:
        return out
    for off in range(0, len(data), step):
        chunk = data[off : off + window]
        if not chunk:
            break
        out.append(
            {
                "offset": off,
                "entropy": round(shannon_entropy(chunk), 4),
                "size": len(chunk),
            }
        )
    return out


def run_triage(path: Path, max_entropy_bytes: int = 4_000_000) -> dict:
    raw = path.read_bytes()
    sample = raw if len(raw) <= max_entropy_bytes else raw[:max_entropy_bytes]
    ent = shannon_entropy(sample)
    ftype = detect_magic(raw[:64])
    findings: list[Finding] = []

    findings.append(
        Finding(
            engine="triage",
            severity="info",
            title="Identidade do artefacto",
            detail=f"tipo={ftype} size={len(raw)} entropy={ent:.3f}",
            evidence=path.name,
            confidence=0.95,
        )
    )

    if ent >= 7.2:
        findings.append(
            Finding(
                engine="triage",
                severity="high",
                title="Entropia elevada (possível packing/crypto/compressão)",
                detail=(
                    f"Entropia Shannon={ent:.3f}. Valores >7.0 costumam indicar "
                    "código empacotado, cifrado ou comprimido."
                ),
                confidence=0.75,
            )
        )
    elif ent <= 1.5 and len(raw) > 64:
        findings.append(
            Finding(
                engine="triage",
                severity="low",
                title="Entropia baixa",
                detail=f"Entropia={ent:.3f} — conteúdo pouco aleatório (padding/zeros/texto).",
                confidence=0.7,
            )
        )

    # PE overlay / DOS stub sanity
    if raw.startswith(b"MZ") and len(raw) >= 0x40:
        e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        if e_lfanew + 4 < len(raw) and raw[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            findings.append(
                Finding(
                    engine="triage",
                    severity="info",
                    title="Assinatura PE válida",
                    detail=f"e_lfanew=0x{e_lfanew:X}",
                    confidence=0.98,
                )
            )

    return {
        "sha256": sha256_file(path),
        "size": len(raw),
        "entropy": ent,
        "file_type": ftype,
        "entropy_map": sliding_entropy(sample),
        "findings": findings,
        "raw": raw,
    }
