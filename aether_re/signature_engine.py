"""Reverse Engineering Graph (AetherRE) — Function ID & Binary Signature Matching Engine.

Provides:
  1. Function Prologue & Opcode Pattern Masking (wildcards for immediate offsets);
  2. PE Import Hash (Imphash) and Export Hash generation;
  3. Locality-Sensitive SimHash for function fuzzy matching;
  4. Standard CRT / Library signature database matching (FLIRT-style).
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any, Sequence

import capstone
import pefile

# Canonical signatures for common CRT / runtime functions (x64)
KNOWN_SIGNATURES = [
    {
        "name": "crt_security_init_cookie",
        "pattern": "48 83 ec 28 48 8b 05 ?? ?? ?? ?? 48 85 c0",
        "description": "Visual C++ __security_init_cookie stack protector init",
    },
    {
        "name": "crt_memset_sse2",
        "pattern": "48 89 c8 48 83 fa 10 ?? ?? ?? ?? 0f 57 c0",
        "description": "CRT optimized memset / zero-memory stub",
    },
    {
        "name": "pe_dll_main_stub",
        "pattern": "48 89 5c 24 08 57 48 83 ec 20 8b da 48 8b f9",
        "description": "Standard Windows DLL Entry Point stub",
    },
    {
        "name": "cjson_delete_prologue",
        "pattern": "48 85 c9 74 ?? 48 89 5c 24 08",
        "description": "cJSON_Delete null check and stack frame initialization",
    },
]


class FunctionSignatureEngine:
    """Extracts binary signatures, Imphash, and matches functions against known patterns."""

    def __init__(self, pe_path: str | Path | None = None):
        self.pe_path = Path(pe_path).resolve() if pe_path else None
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def compute_imphash(self, pe_path: str | Path | None = None) -> str:
        """Computes canonical PE Import Hash (Imphash)."""
        target = Path(pe_path or self.pe_path)
        pe = pefile.PE(str(target), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        imphash = pe.get_imphash()
        return imphash or "0" * 32

    def extract_function_pattern(self, code_bytes: bytes, max_instructions: int = 10) -> str:
        """Disassembles instructions and produces an opcode mask with ?? for variable offsets."""
        tokens: list[str] = []
        count = 0
        for ins in self.md.disasm(code_bytes, 0):
            if count >= max_instructions:
                break
            # If the instruction has memory displacement or relative jump/call, wildcard the operand bytes
            has_variable_operand = any(
                op.type in (capstone.x86.X86_OP_MEM, capstone.x86.X86_OP_IMM) and ins.mnemonic in ("call", "jmp", "mov", "lea", "cmp")
                for op in ins.operands
            )
            raw = ins.bytes
            if len(raw) > 2 and has_variable_operand:
                # Keep first 2-3 opcode bytes, mask out the rest
                prefix = " ".join(f"{b:02x}" for b in raw[: len(raw) - 4])
                mask = " ".join("??" for _ in range(4))
                tokens.append(f"{prefix} {mask}".strip())
            else:
                tokens.append(" ".join(f"{b:02x}" for b in raw))
            count += 1
        return " ".join(tokens)

    def compute_mnemonic_simhash(self, mnemonics: Sequence[str], hash_bits: int = 64) -> int:
        """Computes a 64-bit SimHash of a function's mnemonic sequence for fuzzy similarity."""
        v = [0] * hash_bits
        for m in mnemonics:
            h = int(hashlib.md5(m.encode("utf-8")).hexdigest()[:16], 16)
            for i in range(hash_bits):
                bit = (h >> i) & 1
                v[i] += 1 if bit else -1

        fingerprint = 0
        for i in range(hash_bits):
            if v[i] > 0:
                fingerprint |= 1 << i
        return fingerprint

    def match_known_signatures(self, code_bytes: bytes) -> list[dict[str, Any]]:
        """Matches function code bytes against the known signature catalog."""
        matches = []
        code_hex = " ".join(f"{b:02x}" for b in code_bytes)

        for sig in KNOWN_SIGNATURES:
            pat_parts = sig["pattern"].split()
            pat_len = len(pat_parts)
            if len(code_bytes) < pat_len:
                continue

            matched = True
            for i in range(pat_len):
                if pat_parts[i] == "??":
                    continue
                if f"{code_bytes[i]:02x}" != pat_parts[i]:
                    matched = False
                    break

            if matched:
                matches.append({
                    "signature_name": sig["name"],
                    "description": sig["description"],
                    "pattern_length": pat_len,
                    "confidence": 0.95,
                })
        return matches
