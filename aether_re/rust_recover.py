"""AetherRE Megazord — Rust Stripped Binary Symbol, Crate & Panic Forensics (GEAR-06).

Pure-static, zero-execution analyzer for stripped Rust PE/ELF/Mach-O binaries:
- Rustc version & commit hash fingerprinting
- Cargo registry crate & version extraction (.cargo/registry/src/...)
- Source file (.rs) and panic location recovery from .rdata / .rodata
- Rust symbol demangling (legacy _ZN...17h...E and v0 _R...) via pydemumble + fallback
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

SCHEMA = "re-megazord-rust-recover.v1"
MAX_RUST_BYTES = 256 * 1024 * 1024

_RUSTC_VER_RE = re.compile(rb"rustc/(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)\s*\(([0-9a-fA-F]{7,40})(?:\s+(\d{4}-\d{2}-\d{2}))?\)")
_CARGO_CRATE_RE = re.compile(rb"(?:registry[/\\]src[/\\][^/\\]+[/\\]|cargo[/\\]registry[/\\]src[/\\][^/\\]+[/\\])([a-zA-Z0-9_-]+)-(\d+\.\d+\.\d+(?:[a-zA-Z0-9.+_-]*)?)[/\\]")
_RS_PATH_RE = re.compile(rb"([a-zA-Z0-9_./\\:-]{3,200}\.rs)\b")
_RUST_LEGACY_SYM_RE = re.compile(rb"(?:^|[\x00\s])(_ZN[A-Za-z0-9_$]+?17h[0-9a-f]{16}E)\b")
_RUST_V0_SYM_RE = re.compile(rb"(?:^|[\x00\s])(_R[CNMIXYZ][A-Za-z0-9_$]{4,200})\b")

_RUST_MARKERS = (
    b"core::panicking::",
    b"std::rt::lang_start",
    b"rust_eh_personality",
    b"__rust_alloc",
    b"library\\std\\src\\",
    b"library/std/src/",
    b"rustc/",
)


def _demangle_rust_symbol(sym: str) -> str:
    try:
        import pydemumble  # type: ignore[import-untyped]
        out = pydemumble.demangle(sym)
        if out and out != sym:
            return out
    except Exception:
        pass
    # Pure-Python fallback for legacy _ZN<len><part>...17h<hash>E
    if sym.startswith("_ZN") and sym.endswith("E"):
        pos = 3
        parts: list[str] = []
        while pos < len(sym) - 1:
            j = pos
            while j < len(sym) and sym[j].isdigit():
                j += 1
            if j == pos:
                break
            length = int(sym[pos:j])
            part = sym[j:j + length]
            if not part or j + length > len(sym) - 1:
                break
            parts.append(part)
            pos = j + length
        if parts:
            if len(parts) >= 2 and re.fullmatch(r"h[0-9a-f]{16}", parts[-1]):
                parts = parts[:-1]
            return "::".join(parts).replace("$LT$", "<").replace("$GT$", ">").replace("$C$", ", ").replace("$u20$", " ")
    return sym


def recover_rust_metadata(data: bytes) -> dict[str, Any]:
    """Extract rustc version, crates, .rs source paths, and demangled symbols."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_RUST_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "input_too_large"}
    if not blob:
        return {"schema": SCHEMA, "status": "invalid", "code": "empty_input"}

    markers_found = [m.decode("ascii", errors="ignore") for m in _RUST_MARKERS if m in blob]

    rustc_versions: list[dict[str, str | None]] = []
    for m in _RUSTC_VER_RE.finditer(blob):
        rustc_versions.append({
            "version": m.group(1).decode("utf-8", errors="replace"),
            "commit": m.group(2).decode("utf-8", errors="replace"),
            "date": m.group(3).decode("utf-8", errors="replace") if m.group(3) else None,
        })

    crates_map: dict[str, set[str]] = {}
    for m in _CARGO_CRATE_RE.finditer(blob):
        c_name = m.group(1).decode("utf-8", errors="replace")
        c_ver = m.group(2).decode("utf-8", errors="replace")
        crates_map.setdefault(c_name, set()).add(c_ver)
    crates = [{"name": k, "versions": sorted(v)} for k, v in sorted(crates_map.items())]

    rs_paths: list[str] = []
    seen_paths: set[str] = set()
    for m in _RS_PATH_RE.finditer(blob):
        p = m.group(1).decode("utf-8", errors="replace")
        if p not in seen_paths and ("/" in p or "\\" in p):
            seen_paths.add(p)
            rs_paths.append(p)
            if len(rs_paths) >= 1000:
                break

    mangled_seen: set[str] = set()
    demangled_symbols: list[dict[str, str]] = []
    for rx in (_RUST_LEGACY_SYM_RE, _RUST_V0_SYM_RE):
        for m in rx.finditer(blob):
            raw_sym = m.group(1).decode("utf-8", errors="replace")
            if raw_sym in mangled_seen:
                continue
            mangled_seen.add(raw_sym)
            demangled_symbols.append({
                "mangled": raw_sym,
                "demangled": _demangle_rust_symbol(raw_sym),
            })
            if len(demangled_symbols) >= 1000:
                break

    is_rust = bool(markers_found or rustc_versions or crates or demangled_symbols)
    return {
        "schema": SCHEMA,
        "status": "complete",
        "is_rust_binary": is_rust,
        "markers": markers_found,
        "rustc_versions": rustc_versions,
        "total_crates": len(crates),
        "crates": crates,
        "total_source_paths": len(rs_paths),
        "source_paths": rs_paths,
        "total_demangled_symbols": len(demangled_symbols),
        "demangled_symbols": demangled_symbols,
    }


def scan_file_rust(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_RUST_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    report = recover_rust_metadata(path.read_bytes())
    report["target"] = str(path)
    return report
