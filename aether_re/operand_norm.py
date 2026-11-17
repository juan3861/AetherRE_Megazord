"""Reverse Engineering Graph (AetherRE) — Assembly Operand & Instruction Normalizer.

Inspirado nas abordagens de ponta do PalmTree (CCS) e Asm2Vec (IEEE S&P).
Implementa a normalização semântica de instruções assembly (x86, x64, ARM)
para desacoplar a representação sintática de binários de:
  1. Alocação de registradores voláteis por compiladores;
  2. Offsets variáveis de variáveis locais na pilha;
  3. Endereçamento absoluto vs. relocável (RIP-relative);
  4. Flags e níveis de otimização (-O0, -O2, -O3).

Produz uma assinatura canônica determinística para cada instrução e fluxo.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

# -----------------------------------------------------------------------------
# Dicionários e Padrões de Normalização de Registradores
# -----------------------------------------------------------------------------

# Mapeamento estrito de registradores x86/x64 para papéis semânticos
_X86_REGS: dict[str, str] = {
    # Acumulador
    "rax": "REG_ACC", "eax": "REG_ACC", "ax": "REG_ACC", "al": "REG_ACC", "ah": "REG_ACC",
    # Contador / Argumento 4 (Windows x64) / Argumento 1 (System V)
    "rcx": "REG_CTR", "ecx": "REG_CTR", "cx": "REG_CTR", "cl": "REG_CTR", "ch": "REG_CTR",
    # Dados / Argumento 2
    "rdx": "REG_DATA", "edx": "REG_DATA", "dx": "REG_DATA", "dl": "REG_DATA", "dh": "REG_DATA",
    # Base
    "rbx": "REG_BASE", "ebx": "REG_BASE", "bx": "REG_BASE", "bl": "REG_BASE", "bh": "REG_BASE",
    # Ponteiro de Pilha e Base de Frame
    "rsp": "REG_SP", "esp": "REG_SP", "sp": "REG_SP", "spl": "REG_SP",
    "rbp": "REG_BP", "ebp": "REG_BP", "bp": "REG_BP", "bpl": "REG_BP",
    # Índices Origem e Destino
    "rsi": "REG_SRC", "esi": "REG_SRC", "si": "REG_SRC", "sil": "REG_SRC",
    "rdi": "REG_DST", "edi": "REG_DST", "di": "REG_DST", "dil": "REG_DST",
    # Ponteiro de Instrução
    "rip": "REG_IP", "eip": "REG_IP", "ip": "REG_IP",
}

# Registradores x64 estendidos: r8 a r15 (com variações d, w, b)
for i in range(8, 16):
    _X86_REGS[f"r{i}"] = "REG_EXT"
    _X86_REGS[f"r{i}d"] = "REG_EXT"
    _X86_REGS[f"r{i}w"] = "REG_EXT"
    _X86_REGS[f"r{i}b"] = "REG_EXT"

# Registradores Vetoriais e Ponto Flutuante (XMM, YMM, ZMM, ST)
for i in range(32):
    _X86_REGS[f"xmm{i}"] = "REG_VEC"
    _X86_REGS[f"ymm{i}"] = "REG_VEC"
    _X86_REGS[f"zmm{i}"] = "REG_VEC"
for i in range(8):
    _X86_REGS[f"st{i}"] = "REG_FP"

# Registradores ARM / AArch64 (x0-x30, w0-w30, r0-r7; r8-r15 já mapeados para REG_EXT)
for i in range(31):
    _X86_REGS[f"x{i}"] = f"REG_ARM_G{i}"
    _X86_REGS[f"w{i}"] = f"REG_ARM_G{i}"
for i in range(8):
    _X86_REGS[f"r{i}"] = f"REG_ARM_G{i}"
_X86_REGS["lr"] = "REG_LR"
_X86_REGS["pc"] = "REG_PC"

# Regex para detectar registradores isolados (word boundaries)
_REG_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in sorted(_X86_REGS.keys(), key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

# Padrões para abstração de memória entre colchetes
_STACK_MEM_PATTERN = re.compile(r"\[\s*(?:r|e)?(?:bp|sp)\s*[+-]\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]", re.IGNORECASE)
_STACK_DIRECT_PATTERN = re.compile(r"\[\s*(?:r|e)?(?:bp|sp)\s*\]", re.IGNORECASE)
_RIP_REL_PATTERN = re.compile(r"\[\s*(?:rip|eip)\s*[+-]\s*(?:0x[0-9a-fA-F]+|\d+)\s*\]", re.IGNORECASE)
_INDEXED_MEM_PATTERN = re.compile(r"\[\s*[a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+\s*(?:\*\s*\d+)?\s*(?:[+-]\s*(?:0x[0-9a-fA-F]+|\d+))?\s*\]")
_GEN_MEM_PATTERN = re.compile(r"\[\s*[^\]]+\s*\]")

# Padrões de Imediatos Numéricos
_IMM_HEX_PATTERN = re.compile(r"\b0x[0-9a-fA-F]+\b")
_IMM_DEC_PATTERN = re.compile(r"\b\d+\b")

# Mnemônicos de fluxo de controle
_BRANCH_MNEMONICS = frozenset({
    "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "call",
    "loop", "loope", "loopne", "b", "bl", "bx", "blx", "b.eq", "b.ne",
})


def _replace_reg_match(match: re.Match[str]) -> str:
    key = match.group(0).lower()
    return _X86_REGS.get(key, match.group(0).upper())


def normalize_operands(op_str: str, mnemonic: str = "") -> str:
    """Normaliza uma string de operandos de assembly em uma forma canônica abstrata."""
    if not op_str or not op_str.strip():
        return ""

    s = op_str.strip()

    # 1. Se for instrução de salto ou chamada, normaliza o alvo de desvio
    mnem_lower = mnemonic.strip().lower()
    if mnem_lower in _BRANCH_MNEMONICS:
        # Se o alvo for um imediato/endereço direto
        if _IMM_HEX_PATTERN.fullmatch(s) or _IMM_DEC_PATTERN.fullmatch(s):
            return "TARGET_ADDR"

    # 2. Abstração de Acessos à Memória (pilha, rip, indexado)
    s = _STACK_MEM_PATTERN.sub("[STACK_VAR]", s)
    s = _STACK_DIRECT_PATTERN.sub("[STACK_PTR]", s)
    s = _RIP_REL_PATTERN.sub("[RIP_REL]", s)
    s = _INDEXED_MEM_PATTERN.sub("[INDEXED_MEM]", s)

    # 3. Normalização de Registradores
    s = _REG_PATTERN.sub(_replace_reg_match, s)

    # 4. Abstração de Imediatos Numéricos fora de colchetes
    # Imediatos pequenos comuns (-8 a 8) têm significado semântico fixo (passo/align), outros viram IMM_VAL
    def replace_imm(m: re.Match[str]) -> str:
        raw_val = m.group(0)
        try:
            val = int(raw_val, 16) if raw_val.lower().startswith("0x") else int(raw_val)
            if -8 <= val <= 8:
                return f"IMM_{val}"
            return "IMM_VAL"
        except ValueError:
            return "IMM_VAL"

    # Substitui hexadecimais restantes
    s = _IMM_HEX_PATTERN.sub(replace_imm, s)
    # Substitui decimais restantes que não façam parte de tokens já gerados
    s = re.sub(r"(?<![A-Za-z0-9_])(\d+)(?![A-Za-z0-9_])", replace_imm, s)

    # Limpeza de especificadores de tamanho x86 redundantes
    s = re.sub(r"\b(?:qword|dword|word|byte)\s+ptr\b", "", s, flags=re.IGNORECASE)

    # Normaliza espaçamento entre vírgulas
    s = re.sub(r"\s*,\s*", ", ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def normalize_instruction(mnemonic: str, op_str: str = "") -> tuple[str, str, str]:
    """Retorna (mnemônico_canônico, operandos_normalizados, assinatura_completa)."""
    norm_mnem = mnemonic.strip().upper()
    norm_ops = normalize_operands(op_str, mnemonic=mnemonic)
    signature = f"{norm_mnem} {norm_ops}".strip()
    return norm_mnem, norm_ops, signature


def normalize_instruction_stream(
    instructions: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Recebe uma sequência de instruções (ex: de Capstone) e anota com formas normalizadas."""
    normalized: list[dict[str, Any]] = []
    for ins in instructions:
        mnem = str(ins.get("mnemonic", ""))
        ops = str(ins.get("op_str", ""))
        norm_mnem, norm_ops, sig = normalize_instruction(mnem, ops)
        entry = dict(ins)
        entry["norm_mnemonic"] = norm_mnem
        entry["norm_op_str"] = norm_ops
        entry["signature"] = sig
        normalized.append(entry)
    return normalized
