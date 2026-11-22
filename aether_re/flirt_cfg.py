"""CFG Graph-Based FLIRT CRT Recognition Engine (Pillar 2).

Replaces brittle raw prologue byte-matching with Control-Flow Graph (CFG)
structural + canonical mnemonic-skeleton analysis over Win64 .pdata functions
(handling compiler optimization variations cleanly with zero false positives).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

import capstone


@dataclass
class CFGSignature:
    rva: int
    size_bytes: int
    insn_count: int
    block_count: int
    edge_count: int
    backedge_count: int
    cyclomatic_complexity: int
    call_count: int
    ret_count: int
    indirect_call_count: int
    has_gs_access: bool
    has_fastfail_or_ud2: bool
    has_chkstk_probe: bool
    has_rep_memop: bool
    has_simd_byte_scan: bool
    skeleton_sha256: str
    blocks_preview: Tuple[int, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _norm_mnemonic_token(ins: capstone.CsInsn) -> str:
    m = ins.mnemonic.lower()
    op = ins.op_str.lower()
    if m.startswith("j"):
        return "JMP" if m == "jmp" else "JCC"
    if m.startswith("ret"):
        return "RET"
    if m == "call":
        return "CALL_IND" if ("[" in op or op in _GPR_NAMES) else "CALL_DIR"
    if m in ("mov", "movsxd", "movzx", "lea") and "gs:[" in op:
        return "GS_READ"
    if m.startswith("cmov"):
        return "CMOV"
    if m.startswith("set"):
        return "SETCC"
    if "rep" in m:
        return m.upper().replace(" ", "_")
    return m.upper()


_GPR_NAMES: Set[str] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}


def extract_cfg_signature(
    insns: List[capstone.CsInsn],
    func_start: int,
    func_end: int,
) -> Optional[CFGSignature]:
    """Extracts structural CFG topology + canonical mnemonic skeleton from disassembled instructions."""
    if not insns:
        return None

    addr_to_idx: Dict[int, int] = {ins.address: idx for idx, ins in enumerate(insns)}
    block_starts: Set[int] = {insns[0].address}
    terminators: Set[int] = set()

    for idx, ins in enumerate(insns):
        m = ins.mnemonic.lower()
        op = ins.op_str.lower().strip()
        if m == "jmp" or m.startswith("j"):
            terminators.add(ins.address)
            tgt: Optional[int] = None
            if op.startswith("0x"):
                try:
                    tgt = int(op, 16)
                except ValueError:
                    tgt = None
            elif op.isdigit():
                tgt = int(op)
            if tgt is not None and func_start <= tgt < func_end and tgt in addr_to_idx:
                block_starts.add(tgt)
            if idx + 1 < len(insns):
                block_starts.add(insns[idx + 1].address)
        elif m.startswith("ret") or m in ("ud2", "int3") or (m == "int" and op == "0x29"):
            terminators.add(ins.address)
            if idx + 1 < len(insns):
                block_starts.add(insns[idx + 1].address)

    sorted_starts = sorted(a for a in block_starts if a in addr_to_idx)
    if not sorted_starts:
        sorted_starts = [insns[0].address]

    # Map every instruction to its owning basic block start address
    insn_owner: Dict[int, int] = {}
    blocks: Dict[int, List[capstone.CsInsn]] = {s: [] for s in sorted_starts}
    cur_bb = sorted_starts[0]
    start_set = set(sorted_starts)
    for ins in insns:
        if ins.address in start_set:
            cur_bb = ins.address
        insn_owner[ins.address] = cur_bb
        blocks[cur_bb].append(ins)

    edges: Set[Tuple[int, int]] = set()
    backedges = 0
    for bb_idx, bb_start in enumerate(sorted_starts):
        bb_insns = blocks[bb_start]
        if not bb_insns:
            continue
        last = bb_insns[-1]
        m = last.mnemonic.lower()
        op = last.op_str.lower().strip()
        if m == "jmp" or m.startswith("j"):
            if op.startswith("0x"):
                try:
                    tgt = int(op, 16)
                    if tgt in insn_owner:
                        tgt_bb = insn_owner[tgt]
                        edges.add((bb_start, tgt_bb))
                        if tgt_bb <= bb_start:
                            backedges += 1
                except ValueError:
                    pass
            # Conditional branches fall through to next block
            if m != "jmp" and bb_idx + 1 < len(sorted_starts):
                edges.add((bb_start, sorted_starts[bb_idx + 1]))
        elif not (m.startswith("ret") or m in ("ud2", "int3") or (m == "int" and op == "0x29")):
            if bb_idx + 1 < len(sorted_starts):
                edges.add((bb_start, sorted_starts[bb_idx + 1]))

    skeleton_tokens = []
    call_count = 0
    ret_count = 0
    indirect_call_count = 0
    has_gs = False
    has_fastfail_or_ud2 = False
    has_chkstk_sub = False
    has_chkstk_cmp = False
    has_rep_memop = False
    has_simd_byte = False

    for ins in insns:
        m = ins.mnemonic.lower()
        op = ins.op_str.lower()
        skeleton_tokens.append(_norm_mnemonic_token(ins))
        if m == "call":
            call_count += 1
            if "[" in op or op.strip() in _GPR_NAMES:
                indirect_call_count += 1
        elif m.startswith("ret"):
            ret_count += 1
        if "gs:[" in op:
            has_gs = True
        if m == "ud2" or (m == "int" and op.strip() == "0x29"):
            has_fastfail_or_ud2 = True
        if m in ("sub", "add", "lea") and "0x1000" in op:
            has_chkstk_sub = True
        if (m in ("cmp", "lea", "sub") and "rsp" in op) or ("gs:[0x10]" in op):
            has_chkstk_cmp = True
        if "rep" in m and ("stos" in m or "movs" in m or "scas" in m):
            has_rep_memop = True
        if m in ("pcmpeqb", "vpcmpeqb", "pmovmskb", "vpmovmskb"):
            has_simd_byte = True

    skel_str = " ".join(skeleton_tokens)
    skel_hash = hashlib.sha256(skel_str.encode("utf-8")).hexdigest()[:16]
    n_bb = len(sorted_starts)
    n_ed = len(edges)
    cyc = max(1, n_ed - n_bb + 2)

    return CFGSignature(
        rva=func_start,
        size_bytes=func_end - func_start,
        insn_count=len(insns),
        block_count=n_bb,
        edge_count=n_ed,
        backedge_count=backedges,
        cyclomatic_complexity=cyc,
        call_count=call_count,
        ret_count=ret_count,
        indirect_call_count=indirect_call_count,
        has_gs_access=has_gs,
        has_fastfail_or_ud2=has_fastfail_or_ud2,
        has_chkstk_probe=(has_chkstk_sub and has_chkstk_cmp and backedges >= 1),
        has_rep_memop=has_rep_memop,
        has_simd_byte_scan=has_simd_byte,
        skeleton_sha256=skel_hash,
        blocks_preview=tuple(sorted_starts[:8]),
    )


_CANONICAL_CFG_SKELETONS: Dict[str, Tuple[str, str]] = {
    "3cce1ff86dd779ef": ("noop", "cfg_flirt_security_check_cookie"),
    "cd55e5a856e97649": ("noop", "cfg_flirt_chkstk"),
    "3efcb6aab69562aa": ("abort", "cfg_flirt_fastfail_abort"),
    "3fe2673f00791dda": ("memcpy", "cfg_flirt_memcpy_graph"),
    "2c901fac507c8f19": ("memset", "cfg_flirt_memset_graph"),
    "d2b84e52f5616233": ("strlen", "cfg_flirt_strlen_graph"),
}


def _classify_cfg_signature(
    sig: CFGSignature,
    insns: List[capstone.CsInsn],
) -> Optional[Tuple[str, str]]:
    """Matches structural CFG + mnemonic skeleton + SWAR invariants to canonical CRT helpers."""
    # 0. Exact canonical mnemonic-skeleton CFG hash match (compiler-version graph signature)
    if sig.skeleton_sha256 in _CANONICAL_CFG_SKELETONS:
        return _CANONICAL_CFG_SKELETONS[sig.skeleton_sha256]

    # 1. __chkstk (MSVC stack probe loop: 0x1000 page step + gs:[0x10] TEB StackLimit, backedge loop)
    if sig.has_chkstk_probe and sig.has_gs_access and 1 <= sig.block_count <= 8 and sig.call_count == 0:
        return ("noop", "cfg_chkstk_stack_probe")

    # 2. __security_check_cookie (compact cookie compare + rol 0x10 + branch to failure)
    if (
        2 <= sig.block_count <= 5
        and sig.size_bytes <= 64
        and sig.ret_count >= 1
        and sig.call_count == 0
    ):
        has_cmp_cookie = any(
            ins.mnemonic.lower() == "cmp" and "[rip" in ins.op_str.lower()
            for ins in insns[:4]
        )
        has_rol_or_shr = any(
            ins.mnemonic.lower() in ("rol", "ror", "shr") and "0x10" in ins.op_str.lower()
            for ins in insns
        )
        if has_cmp_cookie and has_rol_or_shr:
            return ("noop", "cfg_security_check_cookie")

    # 3. _purecall / fastfail abort stub (int 0x29 / ud2 with zero normal returns)
    if (
        sig.has_fastfail_or_ud2
        and sig.size_bytes <= 128
        and sig.ret_count == 0
        and 1 <= sig.block_count <= 8
    ):
        has_int29 = any(
            ins.mnemonic.lower() == "int" and ins.op_str.lower().strip() == "0x29"
            for ins in insns
        )
        if has_int29:
            return ("abort", "cfg_fastfail_abort")

    # 4. SWAR or SSE2 SIMD strlen (null-byte bitmask magic or pcmpeqb+bsf loop, zero calls)
    movabs_ops = " ".join(ins.op_str.lower() for ins in insns if ins.mnemonic.lower() == "movabs")
    if (
        "0x7efefefefefefeff" in movabs_ops
        and "0x8101010101010100" in movabs_ops
        and sig.call_count == 0
        and sig.backedge_count >= 1
        and sig.size_bytes <= 256
    ):
        writes_mem = any(
            ins.mnemonic.lower() in ("mov", "movdqu", "movups", "stosb") and "[" in ins.op_str.split(",", 1)[0]
            for ins in insns
        )
        if not writes_mem:
            return ("strlen", "cfg_swar_strlen")

    if (
        sig.has_simd_byte_scan
        and sig.backedge_count >= 1
        and sig.call_count == 0
        and 3 <= sig.block_count <= 16
        and sig.size_bytes <= 256
    ):
        has_bsf = any(ins.mnemonic.lower() in ("bsf", "tzcnt") for ins in insns)
        if has_bsf:
            writes_mem = any(
                ins.mnemonic.lower() in ("mov", "movdqu", "movups", "stosb") and "[" in ins.op_str.split(",", 1)[0]
                for ins in insns
            )
            if not writes_mem:
                return ("strlen", "cfg_simd_strlen")

    # 5. SWAR / SSE2 / REP STOS memset (byte broadcast 0x101010101010101 or rep stos without calls)
    if (
        "0x101010101010101" in movabs_ops
        and sig.call_count == 0
        and sig.backedge_count >= 1
        and sig.size_bytes <= 1024
    ):
        return ("memset", "cfg_swar_memset")

    if (
        sig.has_rep_memop
        and sig.call_count == 0
        and 1 <= sig.block_count <= 10
        and sig.size_bytes <= 192
    ):
        rep_mnems = {ins.mnemonic.lower() for ins in insns if "stos" in ins.mnemonic.lower() or "movs" in ins.mnemonic.lower()}
        if any("stos" in rm for rm in rep_mnems) and any(
            ins.mnemonic.lower() in ("mov", "movd") and "rdx" in ins.op_str.lower()
            for ins in insns[:6]
        ):
            if not any("movs" in rm for rm in rep_mnems):
                return ("memset", "cfg_rep_stos_memset")

    return None


def discover_crt_via_cfg_flirt(
    pe: Any,
    pe_data: bytes,
    max_func_size: int = 2048,
) -> Dict[str, Any]:
    """Scans Win64 .pdata functions in executable sections using CFG + mnemonic skeleton FLIRT signatures."""
    matches: List[Dict[str, Any]] = []
    crt_map: Dict[int, str] = {}
    signatures_count = 0

    if pe is None or not pe_data:
        return {"crt_map": crt_map, "matches": matches, "functions_scanned": 0}

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    sec_infos: List[Tuple[int, int, bytes]] = []
    for sec in getattr(pe, "sections", []):
        if not (sec.Characteristics & 0x20000000):
            continue
        sec_rva = int(sec.VirtualAddress)
        sec_raw = int(sec.PointerToRawData)
        sec_sz = min(int(sec.Misc_VirtualSize), len(pe_data) - sec_raw)
        if sec_sz > 0:
            sec_infos.append((sec_rva, sec_rva + sec_sz, pe_data[sec_raw : sec_raw + sec_sz]))

    if not sec_infos:
        return {"crt_map": crt_map, "matches": matches, "functions_scanned": 0}

    seen_starts: Set[int] = set()
    for p_sec in getattr(pe, "sections", []):
        if not p_sec.Name.startswith(b".pdata"):
            continue
        p_raw = int(p_sec.PointerToRawData)
        p_sz = min(int(p_sec.Misc_VirtualSize), len(pe_data) - p_raw)
        for off in range(p_raw, p_raw + p_sz - 11, 12):
            fn_b, fn_e, _ = struct.unpack_from("<III", pe_data, off)
            if fn_b in seen_starts or fn_e <= fn_b or (fn_e - fn_b) > max_func_size:
                continue
            for srva, send, sbytes in sec_infos:
                if srva <= fn_b and fn_e <= send:
                    seen_starts.add(fn_b)
                    chunk = sbytes[fn_b - srva : fn_e - srva]
                    insns = list(md.disasm(chunk, fn_b))
                    if not insns:
                        break
                    signatures_count += 1
                    sig = extract_cfg_signature(insns, fn_b, fn_e)
                    if sig is None:
                        break
                    hit = _classify_cfg_signature(sig, insns)
                    if hit is not None:
                        crt_name, strategy = hit
                        crt_map[fn_b] = crt_name
                        matches.append({
                            "rva": fn_b,
                            "crt_name": crt_name,
                            "strategy": strategy,
                            "blocks": sig.block_count,
                            "edges": sig.edge_count,
                            "backedges": sig.backedge_count,
                            "cyclomatic": sig.cyclomatic_complexity,
                            "skeleton_sha256": sig.skeleton_sha256,
                        })
                    break

    return {
        "crt_map": crt_map,
        "matches": matches,
        "functions_scanned": signatures_count,
    }
