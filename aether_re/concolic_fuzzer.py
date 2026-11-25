"""Hybrid Coverage-Guided + angr/Z3 Concolic Fuzzer & libFuzzer Harness Synthesizer (v10.0).

Combines fast Unicorn basic-block edge-coverage fuzzing with Z3/angr symbolic branch
inversion (Driller/QSYM style) to penetrate deep magic-number and arithmetic guards,
plus deterministic LLVMFuzzerTestOneInput harness emission for compiled twins.
"""

from __future__ import annotations

import hashlib
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pefile
from unicorn import UC_ARCH_X86, UC_HOOK_BLOCK, UC_MODE_32, UC_MODE_64, UC_PROT_ALL, Uc
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EBP,
    UC_X86_REG_ESP,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSP,
)

from aether_re.symbolic_equivalence import synthesize_branch_inputs_angr

SCHEMA = "re-megazord-concolic-fuzzer.v1"

_FUZZ_CODE_BASE = 0x200000
_FUZZ_STACK_BASE = 0x800000
_FUZZ_STACK_SIZE = 0x20000


def _emulate_vector_coverage(
    code_bytes: bytes,
    vec: Tuple[int, int, int, int],
    *,
    base_va: int = _FUZZ_CODE_BASE,
    is_64: bool = True,
    max_insns: int = 8000,
) -> Tuple[set[int], int]:
    """Executes one input tuple on raw machine code in Unicorn and returns (visited_block_edges, return_val)."""
    import struct

    uc = Uc(UC_ARCH_X86, UC_MODE_64 if is_64 else UC_MODE_32)
    span = ((max(len(code_bytes), 0x1000) + 0xFFF) & ~0xFFF) + 0x4000
    uc.mem_map(base_va, span, UC_PROT_ALL)
    uc.mem_map(_FUZZ_STACK_BASE, _FUZZ_STACK_SIZE, UC_PROT_ALL)
    uc.mem_write(base_va, code_bytes)
    ret_addr = base_va + span - 0x100
    uc.mem_write(ret_addr, b"\xC3\x90\x90\x90")

    sp = _FUZZ_STACK_BASE + _FUZZ_STACK_SIZE - 0x1000
    if is_64:
        uc.mem_write(sp, struct.pack("<Q", ret_addr))
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RBP, sp)
        uc.reg_write(UC_X86_REG_RCX, vec[0] & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_X86_REG_RDX, vec[1] & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_X86_REG_R8, vec[2] & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_X86_REG_R9, vec[3] & 0xFFFFFFFFFFFFFFFF)
    else:
        uc.mem_write(sp, struct.pack("<IIIII", ret_addr, vec[0] & 0xFFFFFFFF, vec[1] & 0xFFFFFFFF, vec[2] & 0xFFFFFFFF, vec[3] & 0xFFFFFFFF))
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EBP, sp)

    edges: set[int] = set()
    st = {"prev": 0}

    def _on_blk(u: Uc, addr: int, sz: int, ud: Any) -> None:
        if addr == ret_addr:
            u.emu_stop()
            return
        edge = (st["prev"] << 1) ^ addr
        edges.add(edge)
        st["prev"] = addr

    uc.hook_add(UC_HOOK_BLOCK, _on_blk)
    try:
        uc.emu_start(base_va, ret_addr, count=max_insns)
    except Exception:
        pass
    ret = uc.reg_read(UC_X86_REG_RAX if is_64 else UC_X86_REG_EAX)
    return edges, ret


def run_hybrid_concolic_fuzz(
    code_bytes: bytes,
    *,
    base_va: int = _FUZZ_CODE_BASE,
    arch: str = "amd64",
    mutation_budget: int = 40,
    max_concolic_states: int = 32,
    seed: int = 1337,
) -> Dict[str, Any]:
    """Runs mutational fuzzing followed by angr symbolic branch synthesis when coverage plateaus."""
    if not code_bytes:
        return {"schema": SCHEMA, "status": "empty_code", "corpus": [], "unique_edges": 0}

    is_64 = arch in ("amd64", "x86_64")
    rng = random.Random(seed)
    corpus: List[Tuple[int, int, int, int]] = [(0, 0, 0, 0), (1, 2, 3, 4), (-1, 0, 0, 0)]
    global_edges: set[int] = set()
    corpus_findings: List[Dict[str, Any]] = []

    def _eval_and_keep(vec: Tuple[int, int, int, int], source: str) -> int:
        edges, ret = _emulate_vector_coverage(code_bytes, vec, base_va=base_va, is_64=is_64)
        new_edges = edges - global_edges
        if new_edges:
            global_edges.update(new_edges)
            if vec not in corpus:
                corpus.append(vec)
            corpus_findings.append({
                "inputs": list(vec),
                "source": source,
                "new_edges": len(new_edges),
                "total_edges": len(global_edges),
                "return_val": hex(ret),
            })
        return len(new_edges)

    for v in list(corpus):
        _eval_and_keep(v, "initial_seed")

    mutational_edges = len(global_edges)
    # Phase 1: Coverage-guided mutation loop
    for _ in range(mutation_budget):
        base = rng.choice(corpus)
        idx = rng.randrange(4)
        mut = list(base)
        choice = rng.randrange(3)
        if choice == 0:
            mut[idx] = mut[idx] ^ rng.choice([1, 2, 4, 8, 0xFF, 0x10000, -1])
        elif choice == 1:
            mut[idx] = mut[idx] + rng.randint(-16, 16)
        else:
            mut[idx] = rng.choice([0, 1, 7, 13, 42, 255, 0x7FFFFFFF, -1])
        _eval_and_keep(tuple(mut), "mutation")
        mutational_edges = max(mutational_edges, len(global_edges))

    # Phase 2: Concolic symbolic escalation via angr + Z3 to crack magic guards
    sym_res = synthesize_branch_inputs_angr(
        code_bytes,
        base_addr=base_va,
        arch=arch,
        max_states=max_concolic_states,
        max_steps=64,
    )
    concolic_added = 0
    for svec in sym_res.get("inputs", []):
        gained = _eval_and_keep(tuple(svec), "angr_concolic")
        if gained > 0:
            concolic_added += 1

    return {
        "schema": SCHEMA,
        "status": "complete",
        "code_sha256": hashlib.sha256(code_bytes).hexdigest(),
        "mutational_edges": mutational_edges,
        "total_unique_edges": len(global_edges),
        "concolic_breakthrough_seeds": concolic_added,
        "corpus": [list(v) for v in corpus],
        "trace_discoveries": corpus_findings,
        "symbolic_states_explored": sym_res.get("states_explored", 0),
    }


def generate_libfuzzer_harness(
    fn_name: str,
    *,
    header_include: str = "include/reconstructed_api.h",
    param_count: int = 4,
    out_path: Optional[str | Path] = None,
) -> str:
    """Emits a ready-to-compile libFuzzer `LLVMFuzzerTestOneInput` C++ fuzz harness."""
    n_args = max(1, min(4, param_count))
    lines = [
        "/* Auto-Generated libFuzzer Target Harness by AetherRE Megazord v10.0 */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <string.h>",
        'extern "C" {',
        f'#include "{header_include}"',
        f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9);",
        "}",
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {',
        "    if (size < 32) return 0;",
        "    int64_t args[4] = {0, 0, 0, 0};",
        f"    memcpy(args, data, sizeof(int64_t) * {n_args});",
        f"    (void){fn_name}(args[0], args[1], args[2], args[3]);",
        "    return 0;",
        "}",
        "",
    ]
    harness = "\n".join(lines)
    if out_path is not None:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(harness, encoding="utf-8")
    return harness
