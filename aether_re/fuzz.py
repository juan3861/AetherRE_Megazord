"""Geração determinística de mutações de seeds; não executa o alvo."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def generate_mutations(seeds: list[bytes], *, budget: int = 100, max_size: int = 4096) -> list[dict[str, Any]]:
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < 0:
        raise ValueError("budget_must_be_nonnegative")
    if isinstance(max_size, bool) or not isinstance(max_size, int) or max_size <= 0:
        raise ValueError("max_size_must_be_positive")
    mutations: list[dict[str, Any]] = []
    for seed_index, seed in enumerate(seeds):
        if not isinstance(seed, bytes):
            raise ValueError("seed_must_be_bytes")
        if len(mutations) >= budget:
            break
        candidates: list[tuple[str, bytes]] = [("truncate", seed[: max(1, len(seed) // 2)]), ("append_zero", seed + b"\x00"), ("flip_first", bytes([seed[0] ^ 0xFF]) + seed[1:] if seed else b"\x00")]
        for operator, value in candidates:
            if len(mutations) >= budget:
                break
            value = value[:max_size]
            mutations.append({"id": f"seed{seed_index}:{operator}", "seed_index": seed_index, "seed_sha256": hashlib.sha256(seed).hexdigest(), "operator": operator, "sha256": hashlib.sha256(value).hexdigest(), "size": len(value), "data_hex": value.hex()})
    return mutations


def write_fuzz_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
