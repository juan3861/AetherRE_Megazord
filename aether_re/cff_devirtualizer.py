"""AetherRE Megazord v8.0 — Control-Flow Flattening (CFF) Devirtualizer & API Hash Rewriter.

Uses CFG back-edge topology + Z3 BitVec(64) state-transition solving to:
  1. Detect OLLVM/Tigress/custom CFF dispatcher loops (`state == CONST` cascades).
  2. Solve concrete/symbolic `state` updates at the end of every flattened case block
     (including XOR/arithmetic-obfuscated state transitions and conditional selects).
  3. Rewrite flattened tail jumps directly to true successor blocks and strip dead
     dispatcher/state bookkeeping code cleanly.
  4. Resolve embedded ROR13/DJB2/FNV1a/CRC32 API hash constants back to symbolic APIs.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

import z3

from aether_re.api_hash_resolve import resolve_api_hash
from aether_re.ir_optimizer import (
    _IRBlock,
    _block_successors,
    _cleanup_cfg,
    _parse_c_function,
    _parse_int_const,
    _subst_vars,
)
from aether_re.mba_synthesizer import eval_c_expr_to_z3, simplify_mba_expr
from aether_re.smt_solver import _c_expr_to_smt_expr

SCHEMA = "re-megazord-cff-devirtualizer.v1"

_EQ_CONST_RE = re.compile(
    r"^\(?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*==\s*\(?\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*\)?$"
)
_CONST_EQ_RE = re.compile(
    r"^\(?\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*\)?\s*==\s*\(?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?$"
)
_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);?\s*$")
_TERNARY_RE = re.compile(r"^\(?\s*(.+?)\s*\)?\s*\?\s*\(?\s*(.+?)\s*\)?\s*:\s*\(?\s*(.+?)\s*\)?$")
_HEX_CONST_RE = re.compile(r"\b(0[xX][0-9a-fA-F]{4,8})\b")


def _extract_state_cmp(cond: str) -> Optional[Tuple[str, int]]:
    s = cond.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        balanced = True
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(s) - 1:
                    balanced = False
                    break
        if balanced:
            s = s[1:-1].strip()
        else:
            break
    m1 = _EQ_CONST_RE.match(s)
    if m1:
        val = _parse_int_const(m1.group(2))
        if val is not None:
            return m1.group(1), val
    m2 = _CONST_EQ_RE.match(s)
    if m2:
        val = _parse_int_const(m2.group(1))
        if val is not None:
            return m2.group(2), val
    # Handle obfuscated constant equality like (state ^ K) == V via Z3 solve
    if "==" in s and any(op in s for op in ("^", "+", "-", "*", "&", "|")):
        lhs_s, rhs_s = s.split("==", 1)
        idents = sorted(set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", lhs_s)) - {"int64_t", "uint64_t", "long"})
        if len(idents) == 1:
            sv = idents[0]
            rhs_val = _parse_int_const(rhs_s.strip())
            if rhs_val is not None:
                try:
                    env: Dict[str, z3.BitVecRef] = {}
                    lhs_bv = eval_c_expr_to_z3(lhs_s.strip(), env, bitwidth=64)
                    slv = z3.Solver()
                    slv.set("timeout", 120)
                    slv.add(lhs_bv == z3.BitVecVal(rhs_val & 0xFFFFFFFFFFFFFFFF, 64))
                    if slv.check() == z3.sat and sv in env:
                        m = slv.model()
                        v = m.eval(env[sv], model_completion=True).as_long()
                        # Check uniqueness
                        slv.add(env[sv] != z3.BitVecVal(v, 64))
                        if slv.check() == z3.unsat:
                            return sv, v
                except Exception:
                    pass
    return None


def _eval_bv64_expr(expr: str, known_vals: Dict[str, int], timeout_ms: int = 120) -> Optional[int]:
    lit = _parse_int_const(expr.strip())
    if lit is not None:
        return lit & 0xFFFFFFFFFFFFFFFF
    expr_sub = _subst_vars(expr.strip(), {k: f"0x{v & 0xFFFFFFFFFFFFFFFF:x}ULL" for k, v in known_vals.items()})
    lit2 = _parse_int_const(expr_sub)
    if lit2 is not None:
        return lit2 & 0xFFFFFFFFFFFFFFFF
    try:
        env: Dict[str, z3.BitVecRef] = {}
        bv = eval_c_expr_to_z3(expr_sub, env, bitwidth=64)
        if not env:
            slv = z3.Solver()
            slv.set("timeout", timeout_ms)
            res_var = z3.BitVec("_res", 64)
            slv.add(res_var == bv)
            if slv.check() == z3.sat:
                return slv.model().eval(res_var, model_completion=True).as_long()
    except Exception:
        pass
    return None


def unflatten_cff_function(
    c_code: str,
    *,
    state_vars: Optional[Set[str]] = None,
    z3_timeout_ms: int = 250,
) -> Tuple[str, Dict[str, Any]]:
    """Recovers real CFG edges from a Control-Flow Flattened (dispatcher-loop) function."""
    parsed = _parse_c_function(c_code)
    if parsed is None:
        return c_code, {"schema": SCHEMA, "dispatchers_removed": 0, "edges_recovered": 0, "cfg_restored": False}

    header_lines, blocks, _ = parsed
    if len(blocks) < 3:
        return c_code, {"schema": SCHEMA, "dispatchers_removed": 0, "edges_recovered": 0, "cfg_restored": False}

    name_to_idx = {b.name: i for i, b in enumerate(blocks)}
    label_to_block = {b.label: b.name for b in blocks if b.label}
    _, succs = _block_successors(blocks)
    preds: Dict[str, List[str]] = {b.name: [] for b in blocks}
    for u, vs in succs.items():
        for v in vs:
            if v in preds:
                preds[v].append(u)

    # Identify candidate dispatcher root: block with high in-degree (>= 2) whose fallthrough chain matches state == C
    dispatchers_removed = 0
    edges_recovered = 0
    resolved_state_vars: Set[str] = set()
    used_dispatch_nodes: Set[str] = set()

    for root_blk in blocks:
        if len(preds.get(root_blk.name, ())) < 2:
            continue
        # Follow linear dispatcher cascade (cbranch -> fallthrough -> cbranch ...)
        state_to_target: Dict[int, str] = {}
        cascade_nodes: List[str] = []
        detected_var: Optional[str] = None
        default_target: Optional[str] = None

        cur_name: Optional[str] = root_blk.name
        seen_cascade: Set[str] = set()
        cascade_env: Dict[str, str] = {}
        while cur_name and cur_name not in seen_cascade:
            seen_cascade.add(cur_name)
            cb = blocks[name_to_idx[cur_name]]
            if cb.stmts:
                if len(cb.stmts) > 4:
                    break
                all_temp_assigns = True
                for st in cb.stmts:
                    m_st = _ASSIGN_RE.match(st.strip())
                    if not m_st:
                        all_temp_assigns = False
                        break
                    cascade_env[m_st.group(1)] = _subst_vars(m_st.group(2).strip(), cascade_env)
                if not all_temp_assigns:
                    break
            if cb.term_kind == "cbranch":
                eff_cond = _subst_vars(cb.term_cond, cascade_env) if cascade_env else cb.term_cond
                cmp_res = _extract_state_cmp(eff_cond)
                if cmp_res is None:
                    break
                sv_name, sv_val = cmp_res
                if state_vars and sv_name not in state_vars:
                    break
                if detected_var is None:
                    detected_var = sv_name
                elif detected_var != sv_name:
                    break
                tgt_name = label_to_block.get(cb.term_target)
                if tgt_name is None:
                    break
                state_to_target[sv_val & 0xFFFFFFFFFFFFFFFF] = tgt_name
                cascade_nodes.append(cur_name)
                ci = name_to_idx[cur_name]
                cur_name = blocks[ci + 1].name if ci + 1 < len(blocks) else None
            elif cb.term_kind == "goto":
                default_target = label_to_block.get(cb.term_target)
                cascade_nodes.append(cur_name)
                break
            else:
                break

        if detected_var is None or len(state_to_target) < 2:
            continue

        cascade_set = set(cascade_nodes)
        resolved_state_vars.add(detected_var)

        # Find initial state reaching root_blk from any pre-dispatcher entry block
        # and rewrite every predecessor block that assigns `detected_var` and jumps to `root_blk`.
        rewrote_any = False
        for pred_name in list(preds.get(root_blk.name, ())):
            if pred_name in cascade_set:
                continue
            pb = blocks[name_to_idx[pred_name]]
            known: Dict[str, int] = {}
            if pb.name == blocks[0].name:
                for hl in header_lines:
                    for m_init in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\b", hl):
                        iv = _parse_int_const(m_init.group(2))
                        if iv is not None:
                            known[m_init.group(1)] = iv & 0xFFFFFFFFFFFFFFFF
            cond_branch: Optional[Tuple[str, int, int]] = None
            new_stmts: List[str] = []

            for st in pb.stmts:
                m_as = _ASSIGN_RE.match(st.strip())
                if not m_as:
                    new_stmts.append(st)
                    continue
                lhs, rhs = m_as.group(1), m_as.group(2).strip()
                if lhs == detected_var:
                    m_tern = _TERNARY_RE.match(rhs)
                    if m_tern:
                        c_s, t_s, f_s = m_tern.group(1), m_tern.group(2), m_tern.group(3)
                        tv = _eval_bv64_expr(t_s, known, z3_timeout_ms)
                        fv = _eval_bv64_expr(f_s, known, z3_timeout_ms)
                        if tv is not None and fv is not None:
                            cond_branch = (c_s, tv, fv)
                            continue
                    val = _eval_bv64_expr(rhs, known, z3_timeout_ms)
                    if val is not None:
                        known[detected_var] = val
                        cond_branch = None
                        continue
                else:
                    v_other = _eval_bv64_expr(rhs, known, z3_timeout_ms)
                    if v_other is not None:
                        known[lhs] = v_other
                new_stmts.append(st)

            # Check if conditional state switch resolved cleanly
            if cond_branch is not None:
                c_s, tv, fv = cond_branch
                t_blk = state_to_target.get(tv) or default_target
                f_blk = state_to_target.get(fv) or default_target
                if t_blk and f_blk:
                    t_lbl = blocks[name_to_idx[t_blk]].label or t_blk
                    f_lbl = blocks[name_to_idx[f_blk]].label or f_blk
                    pb.stmts = new_stmts
                    pb.stmts.append(f"if ({c_s}) goto {t_lbl};")
                    pb.term_kind = "goto"
                    pb.term_target = f_lbl
                    pb.term_cond = ""
                    edges_recovered += 2
                    rewrote_any = True
                    continue

            if detected_var in known:
                st_val = known[detected_var]
                nxt_blk = state_to_target.get(st_val) or default_target
                if nxt_blk and pb.term_kind in ("goto", "fall"):
                    nxt_lbl = blocks[name_to_idx[nxt_blk]].label or nxt_blk
                    pb.stmts = new_stmts
                    pb.term_kind = "goto"
                    pb.term_target = nxt_lbl
                    pb.term_cond = ""
                    edges_recovered += 1
                    rewrote_any = True

        if rewrote_any:
            dispatchers_removed += 1
            used_dispatch_nodes.update(cascade_nodes)

    if dispatchers_removed == 0:
        return c_code, {"schema": SCHEMA, "dispatchers_removed": 0, "edges_recovered": 0, "cfg_restored": False}

    # Re-render and run IR CFG cleanup to drop unreferenced dispatcher blocks & thread jumps
    returns_double = any(ln.strip().startswith("double ") for ln in header_lines[:2])
    cleaned_blocks = _cleanup_cfg(blocks, returns_double)

    # Prune now-unused pure declarations for resolved state vars when no longer referenced
    body_text_check = "\n".join(
        "\n".join(b.stmts) + f"\n{b.term_cond}\n{b.term_ret}"
        for b in cleaned_blocks
    )
    out_lines: List[str] = []
    for hl in header_lines:
        new_hl = hl
        for sv in resolved_state_vars:
            if not re.search(rf"\b{re.escape(sv)}\b", body_text_check):
                new_hl = re.sub(rf"\bint64_t\s+{re.escape(sv)}\s*=\s*-?\d+\s*;\s*", "", new_hl)
        if new_hl.strip():
            out_lines.append(new_hl)

    for i, b in enumerate(cleaned_blocks):
        if i == 0 and b.label:
            out_lines.append(f"{b.label}: ; /* entry */")
        elif b.label:
            tag = "switch case" if b.pinned_label else "bb"
            out_lines.append(f"{b.label}: ; /* {tag} */")
        for st in b.stmts:
            m_as = _ASSIGN_RE.match(st.strip())
            if m_as and any(op in m_as.group(2) for op in ("^", "&", "|", "+", "*")) and "(" in m_as.group(2):
                mba_r = simplify_mba_expr(m_as.group(2))
                if mba_r.get("proven") and len(mba_r["simplified"]) < len(m_as.group(2)):
                    st = f"{m_as.group(1)} = {mba_r['simplified']}"
            out_lines.append(f"    {st};" if not st.endswith((";", "}")) else f"    {st}")
        if b.term_kind == "return":
            out_lines.append(f"    return {b.term_ret};")
        elif b.term_kind == "goto":
            out_lines.append(f"    if (1) goto {b.term_target};")
        elif b.term_kind == "cbranch":
            out_lines.append(f"    if ({b.term_cond}) goto {b.term_target};")
    out_lines.append("}")

    return "\n".join(out_lines), {
        "schema": SCHEMA,
        "dispatchers_removed": dispatchers_removed,
        "edges_recovered": edges_recovered,
        "state_vars": sorted(resolved_state_vars),
        "cfg_restored": True,
    }


def rewrite_api_hashes_in_c(
    c_code: str,
    *,
    extra_hashes: Optional[Dict[int, Tuple[str, str]]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Detects embedded 32-bit API hashes inside lifted C statements and annotates resolved Win32/POSIX APIs."""
    resolved: List[Dict[str, Any]] = []
    seen_apis: Set[str] = set()
    out_lines: List[str] = []

    for ln in c_code.splitlines():
        notes: List[str] = []
        for m in _HEX_CONST_RE.finditer(ln):
            val = int(m.group(1), 16) & 0xFFFFFFFF
            hits = list(resolve_api_hash(val))
            if extra_hashes and val in extra_hashes:
                alg, api_nm = extra_hashes[val]
                hits.insert(0, {"algorithm": alg, "api_name": api_nm, "hash_hex": hex(val)})
            if hits:
                top = hits[0]
                api_nm = top["api_name"]
                notes.append(f"{top['algorithm']}:{api_nm}")
                if api_nm not in seen_apis:
                    seen_apis.add(api_nm)
                    resolved.append({
                        "hash_hex": hex(val),
                        "algorithm": top["algorithm"],
                        "api_name": api_nm,
                    })
        if notes and "aether_api_hash:" not in ln:
            out_lines.append(f"{ln} /* aether_api_hash:{','.join(notes)} */")
        else:
            out_lines.append(ln)

    return "\n".join(out_lines), {
        "schema": SCHEMA,
        "resolved_count": len(resolved),
        "resolved_apis": resolved,
        "unique_api_names": sorted(seen_apis),
    }
