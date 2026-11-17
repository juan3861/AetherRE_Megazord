"""Block-aware register SSA over a bounded x86 def/use subset.

This constructs identities and predecessor-indexed phi nodes. It does not
prove machine semantics, memory, aliases, ABI or concrete flag predicates.
"""
from __future__ import annotations
import re
from collections import defaultdict
from typing import Any, Sequence
from aether_re.cfg_dominance import compute_immediate_dominators_pure, compute_dominance_frontier

SCHEMA = "ssa-ir-report.v1"
_REG = re.compile(r"(?:r(?:ax|bx|cx|dx|si|di|sp|bp)|e(?:ax|bx|cx|dx|si|di|sp|bp)|ax|bx|cx|dx|si|di|sp|bp|[abcd][lh]|r(?:[89]|1[0-5])(?:[dwb])?)\Z")
_IMM = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)\Z")
_JCC = set("ja jae jb jbe jc je jg jge jl jle jna jnae jnb jnbe jnc jne jng jnge jnl jnle jno jnp jns jnz jo jp jpe jpo js jz".split())


def lift_to_ssa_ir(instructions: Sequence[dict[str, Any]],
                   cfg_edges: Sequence[tuple[str,str]] | None = None,
                   entry: str = "entry") -> dict[str, Any]:
    """Require explicit instruction ``block`` with CFG; version register live-ins as name_0.

    Empty blocks can be declared by edges. Unsupported instructions remain
    visible and make the result partial instead of inventing assignments.
    """
    report = dict(schema=SCHEMA,entry_point=entry,status="invalid",ssa_valid=False,
                  total_lifted_instructions=0,total_variables_versioned=0,
                  phi_nodes_count=0,phi_nodes=[],ssa_instructions=[],live_in_values=[],
                  unreachable_blocks=[],unmodeled_instructions=[],limitations=[],errors=[],
                  semantic_equivalence_proved=False,return_register_assumption="rax",
                  scope="register_def_use_and_cfg_phi; not machine semantics or ABI recovery")
    try:
        if (not isinstance(instructions,(list,tuple)) or len(instructions)>20000
                or not isinstance(entry,str) or not entry or len(entry)>128):
            raise ValueError("invalid_instruction_collection_or_entry")
        if cfg_edges is not None and (not isinstance(cfg_edges,(list,tuple)) or len(cfg_edges)>20000):
            raise ValueError("invalid_cfg_or_edge_budget")
        edges,blocks=set(),{entry}
        for edge in cfg_edges or []:
            if (not isinstance(edge,(tuple,list)) or len(edge)!=2
                    or any(not isinstance(n,str) or not n or len(n)>128 for n in edge)):
                raise ValueError("invalid_cfg_edge")
            edges.add(tuple(edge)); blocks.update(edge)
        grouped=defaultdict(list)
        for index,raw in enumerate(instructions):
            if not isinstance(raw,dict): raise ValueError("invalid_instruction")
            if cfg_edges and "block" not in raw: raise ValueError("instruction_block_mapping_required")
            block=raw.get("block",entry)
            if not isinstance(block,str) or not block or len(block)>128: raise ValueError("invalid_instruction_block")
            mnemonic,text=raw.get("mnemonic",""),raw.get("op_str","")
            if not isinstance(mnemonic,str) or not isinstance(text,str) or len(text)>4096:
                raise ValueError("invalid_instruction_text")
            if "," in text and any(not part.strip() for part in text.split(",")):
                raise ValueError("malformed_operand_list")
            grouped[block].append((index,mnemonic.lower().strip(),text.strip()))
            blocks.add(block)
        if len(blocks)>1024: raise ValueError("block_budget_exceeded")
        successors={b:[] for b in blocks}
        for source,target in sorted(edges): successors[source].append(target)
        reachable,pending=set(),[entry]
        while pending:
            node=pending.pop()
            if node not in reachable:
                reachable.add(node); pending.extend(successors[node])
        report["unreachable_blocks"]=sorted(blocks-reachable)
        nodes=sorted(reachable)
        active_edges=sorted((s,t) for s,t in edges if s in reachable and t in reachable)
        predecessors={b:[] for b in nodes}
        for source,target in active_edges: predecessors[target].append(source)
        if predecessors[entry]: raise ValueError("entry_backedge_requires_explicit_preheader")
        idoms=compute_immediate_dominators_pure(nodes,active_edges,entry)
        frontiers=compute_dominance_frontier(nodes,active_edges,idoms)
        children={b:[] for b in nodes}
        for block,parent in idoms.items():
            if block!=entry and parent is not None: children[parent].append(block)

        rows=defaultdict(list); sites=defaultdict(set); registers=set()
        def operand(token):
            if _REG.fullmatch(token): registers.add(token); return token
            if _IMM.fullmatch(token): return token
            raise ValueError("unmodeled_operand")

        for block in nodes:
            block_rows=grouped[block]
            for position,(_,mnem,text) in enumerate(block_rows):
                if mnem in _JCC | {"jmp","ret"}:
                    if position!=len(block_rows)-1: raise ValueError("instruction_after_terminator")
                    if mnem=="ret" and successors[block]: raise ValueError("return_has_cfg_successors")
                    if cfg_edges is not None and mnem in _JCC | {"jmp"}:
                        direct = not _REG.fullmatch(text.lower()) and re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$]*|(?:0[xX])?[0-9a-fA-F]+",text)
                        if direct and (text not in successors[block] or
                                       mnem=="jmp" and successors[block]!=[text]):
                            raise ValueError("branch_target_cfg_mismatch")
            for index,mnem,text in grouped[block]:
                ops=[p.strip().lower() for p in text.split(",") if p.strip()]
                row=dict(index=index,block=block,raw_instruction=f"{mnem} {text}".rstrip(),
                         op="UNMODELED",dest=None,srcs=[],definitions=[],_defs=[],_uses=[],target=None)
                try:
                    if mnem in {"mov","movzx","movsx","movsxd"} and len(ops)==2:
                        if not _REG.fullmatch(ops[0]): raise ValueError("memory_write_not_modeled")
                        row.update(op="ASSIGN" if mnem=="mov" else "ASSIGN_"+mnem.upper(),
                                   _defs=[operand(ops[0])],_uses=[operand(ops[1])])
                    elif mnem in {"add","sub","imul","and","or","xor"} and len(ops)==2:
                        if not _REG.fullmatch(ops[0]): raise ValueError("non_register_destination")
                        row.update(op="BINOP_"+mnem.upper(),_defs=[operand(ops[0]),"flags"],
                                   _uses=[operand(ops[0]),operand(ops[1])])
                    elif mnem in {"cmp","test"} and len(ops)==2:
                        row.update(op="COMPARE_"+mnem.upper(),_defs=["flags"],_uses=[operand(o) for o in ops])
                    elif mnem in _JCC and len(ops)==1:
                        if _REG.fullmatch(ops[0]) or not re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$]*|(?:0[xX])?[0-9a-fA-F]+",text):
                            raise ValueError("indirect_branch_not_modeled")
                        row.update(op="CBRANCH",_uses=["flags"],target=text,condition_code=mnem)
                    elif mnem=="jmp" and len(ops)==1:
                        if _REG.fullmatch(ops[0]) or not re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$]*|(?:0[xX])?[0-9a-fA-F]+",text):
                            raise ValueError("indirect_branch_not_modeled")
                        row.update(op="BRANCH",target=text)
                    elif mnem=="ret" and not ops:
                        row.update(op="RETURN",_uses=["rax"]); registers.add("rax")
                    elif mnem=="nop" and not ops: row.update(op="NOP")
                    else: raise ValueError("unsupported_opcode_or_arity")
                except ValueError as exc:
                    row.update(op="UNMODELED",_defs=[],_uses=[],unmodeled_reason=str(exc))
                    report["unmodeled_instructions"].append(index)
                for variable in row["_defs"]: sites[variable].add(block)
                rows[block].append(row)

        aliases=defaultdict(set)
        families={"rax":("rax","eax","ax","al","ah"),"rbx":("rbx","ebx","bx","bl","bh"),
                  "rcx":("rcx","ecx","cx","cl","ch"),"rdx":("rdx","edx","dx","dl","dh"),
                  "rsi":("rsi","esi","si"),"rdi":("rdi","edi","di"),
                  "rsp":("rsp","esp","sp"),"rbp":("rbp","ebp","bp")}
        for register in registers:
            family=next((root for root,names in families.items() if register in names),register)
            if re.fullmatch(r"r(?:[89]|1[0-5])[dwb]?",register): family=register.rstrip("dwb")
            aliases[family].add(register)
        if any(len(names)>1 for names in aliases.values()):
            report["limitations"].append("register_alias_overlap_not_modeled")

        phis={b:{} for b in nodes}
        phi_count=0
        for variable,defsites in sorted(sites.items()):
            work,queued=sorted(defsites),set(defsites)
            while work:
                source=work.pop()
                for target in frontiers[source]:
                    if variable not in phis[target]:
                        phi_count+=1
                        if phi_count>20000: raise ValueError("phi_budget_exceeded")
                        phis[target][variable]=dict(block=target,variable=variable,dest=None,
                                                    predecessors=predecessors[target],_incoming={})
                        if target not in queued: queued.add(target); work.append(target)
        counters,stacks=defaultdict(int),defaultdict(list)
        liveins=set()
        def read(variable):
            if _IMM.fullmatch(variable): return variable
            if stacks[variable]: return stacks[variable][-1]
            name=variable+"_0"; liveins.add(name); return name
        def write(variable,pushed):
            counters[variable]+=1
            name=f"{variable}_{counters[variable]}"
            stacks[variable].append(name); pushed.append(variable); return name

        events,lifted=[("enter",entry,None)],[]
        while events:
            phase,block,pushed=events.pop()
            if phase=="exit":
                for variable in reversed(pushed): stacks[variable].pop()
                continue
            pushed=[]
            for variable,phi in sorted(phis[block].items()): phi["dest"]=write(variable,pushed)
            for row in rows[block]:
                row["srcs"]=[read(v) for v in row.pop("_uses")]
                defs=row.pop("_defs")
                row["definitions"]=[write(v,pushed) for v in defs]
                if row["definitions"]:
                    row["dest"]=row["definitions"][0]
                    if "flags" in defs: row["flag_dest"]=row["definitions"][defs.index("flags")]
                lifted.append(row)
            for successor in successors[block]:
                for variable,phi in phis[successor].items(): phi["_incoming"][block]=read(variable)
            events.append(("exit",block,pushed))
            for child in sorted(children[block],reverse=True): events.append(("enter",child,None))
        phi_nodes=[]
        for block in nodes:
            for _,phi in sorted(phis[block].items()):
                incoming=phi.pop("_incoming")
                if set(incoming)!=set(phi["predecessors"]): raise ValueError("incomplete_phi_predecessors")
                phi["sources"]=[incoming[p] for p in phi["predecessors"]]; phi_nodes.append(phi)
        partial=bool(report["unmodeled_instructions"] or report["limitations"])
        report.update(status="partial" if partial else "complete",ssa_valid=not partial,
                      total_lifted_instructions=len(lifted),total_variables_versioned=len(counters),
                      phi_nodes_count=len(phi_nodes),phi_nodes=phi_nodes,
                      ssa_instructions=sorted(lifted,key=lambda row:row["index"]),live_in_values=sorted(liveins),
                      immediate_dominators=idoms,dominance_frontiers=frontiers,
                      modeled_instruction_count=len(lifted)-len(report["unmodeled_instructions"]))
        report["limitations"].extend(["register_names_are_distinct_abstract_variables",
                                      "no_memory_width_ABI_or_concrete_flag_semantics"])
    except (ValueError,TypeError,KeyError) as exc:
        report["errors"].append(str(exc))
    return report
