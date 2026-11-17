"""Reverse Engineering Graph (AetherRE) — 64-Bit Function SimHash & Distance Engine.

Implementa a vetorização densa de funções binárias baseada em SimHash de 64 bits
(Locality-Sensitive Hashing), inspirada na arquitetura do Google Project Zero
(FunctionSimSearch) e nos princípios de Self-Attentive Function Embeddings (SAFE).

Permite:
  1. Indexação de milhares de funções binárias por segundo;
  2. Cálculo de similaridade contínua via distância de Hamming em sub-milissegundos;
  3. Pareamento robusto de funções entre compilações com diferentes otimizações;
  4. Resiliência a mutações locais através de n-gramas de instruções normalizadas.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

from aether_re.operand_norm import normalize_instruction_stream

# FNV-1a 64-bit constantes determinísticas
_FNV_OFFSET_BASIS_64 = 0xCBF29CE484222325
_FNV_PRIME_64 = 0x100000001B3
_MASK_64 = 0xFFFFFFFFFFFFFFFF


def _fnv1a_64(data: bytes) -> int:
    """Calcula hash FNV-1a de 64 bits ultra-rápido e determinístico."""
    h = _FNV_OFFSET_BASIS_64
    for b in data:
        h = ((h ^ b) * _FNV_PRIME_64) & _MASK_64
    return h


def _extract_ngrams(items: Sequence[str], n: int = 3) -> list[str]:
    """Extrai n-gramas ordenados de uma sequência de strings."""
    if not items:
        return []
    if len(items) <= n:
        return ["__".join(items)]
    return ["__".join(items[i : i + n]) for i in range(len(items) - n + 1)]


def compute_function_simhash(
    instructions: Sequence[dict[str, Any]],
    *,
    n: int = 3,
    normalize: bool = True,
) -> str:
    """Computa o SimHash de 64 bits de uma sequência de instruções de função.

    Retorna uma string hexadecimal de 16 caracteres (ex: '0123456789abcdef').
    """
    if not instructions:
        return "0000000000000000"

    # Se ainda não normalizado, passa pelo normalizador PalmTree
    if normalize and not instructions[0].get("signature"):
        stream = normalize_instruction_stream(instructions)
    else:
        stream = list(instructions)

    signatures = [str(ins.get("signature") or ins.get("mnemonic", "")) for ins in stream]
    ngrams = _extract_ngrams(signatures, n=n)

    # Vetor de acumulação de 64 posições
    v = [0.0] * 64

    for gram in ngrams:
        gram_bytes = gram.encode("utf-8", errors="replace")
        h64 = _fnv1a_64(gram_bytes)

        # Ponderação semântica: tokens de desvio/chamada e retorno ganham peso maior
        weight = 1.0
        if any(k in gram for k in ("CALL", "JMP", "RET", "JZ", "JNZ")):
            weight = 1.5

        for i in range(64):
            bit = (h64 >> i) & 1
            if bit == 1:
                v[i] += weight
            else:
                v[i] -= weight

    # Constrói o hash final de 64 bits
    simhash_val = 0
    for i in range(64):
        if v[i] > 0:
            simhash_val |= 1 << i

    return f"{simhash_val:016x}"


def hamming_distance(h1: str | int, h2: str | int) -> int:
    """Calcula o número de bits diferentes entre dois SimHashes de 64 bits (0 a 64)."""
    v1 = int(h1, 16) if isinstance(h1, str) else int(h1)
    v2 = int(h2, 16) if isinstance(h2, str) else int(h2)
    xor_val = (v1 ^ v2) & _MASK_64
    return bin(xor_val).count("1")


def simhash_similarity(h1: str | int, h2: str | int) -> float:
    """Converte a distância de Hamming em índice de similaridade contínuo [0.0, 1.0]."""
    dist = hamming_distance(h1, h2)
    return round((64.0 - dist) / 64.0, 4)


def extract_binary_simhashes(target_path: Path | str, is_64: bool = True) -> dict[str, dict[str, Any]]:
    """Extrai e calcula SimHashes de todas as funções observáveis de um binário."""
    p = Path(target_path)
    if not p.is_file():
        raise FileNotFoundError(f"Binário não encontrado: {target_path}")

    raw = p.read_bytes()
    from aether_re.engines import disasm, pe_elf, triage

    magic = triage.detect_magic(raw[:64])
    struct_info = pe_elf.run_structure(raw)

    profiles: dict[str, dict[str, Any]] = {}

    # 1. Entry point disassembly
    dis_res = disasm.run_disasm(raw, is_64=is_64, file_format=magic)
    for snip in dis_res.get("snippets", []):
        insns = snip.get("instructions", [])
        if insns:
            name = snip.get("region", "entry_point")
            sh = compute_function_simhash(insns)
            profiles[name] = {
                "address": snip.get("base", "0x1000"),
                "name": name,
                "insn_count": len(insns),
                "simhash": sh,
            }

    # 2. Exports e símbolos observados
    for exp in struct_info.get("exports", []):
        if exp not in profiles:
            # Hash sintético determinístico baseado na assinatura semântica do export
            sh_exp = f"{_fnv1a_64(f'EXPORT_{exp}'.encode()):016x}"
            profiles[exp] = {
                "address": "export",
                "name": exp,
                "insn_count": 0,
                "simhash": sh_exp,
            }

    return profiles
