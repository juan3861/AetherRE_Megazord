"""Validate observed High P-Code and project its CFG/def-use into the common IR.

Structural checks establish consistency of the supplied decompiler export,
never original source, ABI recovery or binary semantic equivalence.
"""
from __future__ import annotations

import re

from aether_re.cfg_dominance import compute_immediate_dominators_pure
from aether_re.ir import IRDocument, IREdge, IRLocation, IRNode, canonical_ir_dict
from aether_re.kernel_contracts import EpistemicState

MAX_BLOCKS, MAX_OPS, MAX_VARNODES, MAX_EDGES = 512, 8192, 32768, 4096
_HEX = re.compile(r"[0-9a-fA-F]{1,16}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_BINARY = set("INT_ADD INT_SUB INT_MULT INT_DIV INT_SDIV INT_REM INT_SREM INT_XOR INT_AND INT_OR".split())
_COMPARE = set("INT_EQUAL INT_NOTEQUAL INT_LESS INT_LESSEQUAL INT_SLESS INT_SLESSEQUAL INT_CARRY INT_SCARRY INT_SBORROW".split())
_UNARY = {"COPY", "CAST", "INT_2COMP", "INT_NEGATE"}
_CONTROL = {"BRANCH", "CBRANCH", "BRANCHIND", "RETURN"}
_CALLS = {"CALL", "CALLIND", "CALLOTHER"}
_KNOWN = (_BINARY | _COMPARE | _UNARY | _CONTROL | _CALLS |
          set("LOAD STORE MULTIEQUAL INDIRECT INT_ZEXT INT_SEXT INT_LEFT INT_RIGHT INT_SRIGHT PIECE SUBPIECE PTRADD PTRSUB BOOL_NEGATE BOOL_XOR BOOL_AND BOOL_OR POPCOUNT LZCOUNT".split()))


def _require(condition, error):
    if not condition:
        raise ValueError(error)


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def canonical_address(value):
    _require(isinstance(value, str), "pcode_address_invalid")
    match = re.fullmatch(r"([A-Za-z0-9_.-]{1,64}):([0-9a-fA-F]{1,16})", value)
    _require(match is not None, "pcode_address_invalid")
    return match[1] + ":" + format(int(match[2], 16), "x")


def _inventory(items, maximum, label):
    _require(isinstance(items, list) and len(items) <= maximum, "pcode_" + label + "_budget")
    result = {}
    for item in items:
        _require(isinstance(item, dict) and isinstance(item.get("id"), str) and _ID.fullmatch(item["id"]), "pcode_" + label + "_identity")
        _require(item["id"] not in result, "pcode_" + label + "_duplicate")
        result[item["id"]] = item
    return result


def _dominates(header, node, idom):
    while node is not None:
        if header == node:
            return True
        parent = idom[node]
        if parent == node:
            break
        node = parent
    return False


def analyze_high_pcode(data, *, expected_target, expected_address, evidence_sha256):
    _require(isinstance(data, dict) and data.get("schema") == "ghidra-high-pcode.v1", "pcode_schema_invalid")
    _require(re.fullmatch(r"[0-9a-f]{64}", expected_target or "") is not None and data.get("target_sha256") == expected_target,
             "pcode_target_mismatch")
    address = canonical_address(expected_address)
    _require(canonical_address(data.get("function_address")) == address, "pcode_function_mismatch")
    _require(re.fullmatch(r"[0-9a-f]{64}", evidence_sha256 or "") is not None, "pcode_evidence_hash_invalid")
    _require(type(data.get("complete")) is bool, "pcode_completeness_invalid")
    for claim in ("semantic_equivalence_proved", "binary_semantics_recovered", "original_source_recovered"):
        _require(data.get(claim, False) is False, "pcode_unproved_claim")
    context = data.get("context")
    _require(isinstance(context, dict), "pcode_context_missing")
    for key in ("language_id", "compiler_spec_id"):
        _require(isinstance(context.get(key), str) and 0 < len(context[key]) <= 256, "pcode_context_invalid")
    _require(context.get("endian") in {"little", "big"} and _integer(context.get("address_bits"), 1, 64), "pcode_context_invalid")
    canonical_address(context.get("image_base"))
    raw_spaces = context.get("spaces")
    _require(isinstance(raw_spaces, list) and 1 <= len(raw_spaces) <= 256, "pcode_spaces_invalid")
    spaces, space_ids = {}, set()
    for space in raw_spaces:
        _require(isinstance(space, dict) and isinstance(space.get("name"), str)
                 and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", space["name"]), "pcode_space_invalid")
        _require(space["name"] not in spaces and space.get("id") not in space_ids
                 and _integer(space.get("id"), -(2**31), 2**31-1)
                 and _integer(space.get("bits"), 1, 64) and _integer(space.get("word_size"), 1, 16)
                 and space.get("kind") in {"constant", "register", "unique", "memory", "stack", "other"}, "pcode_space_invalid")
        spaces[space["name"]] = space
        space_ids.add(space["id"])
    blocks = _inventory(data.get("blocks"), MAX_BLOCKS, "blocks")
    ops = _inventory(data.get("operations"), MAX_OPS, "operations")
    variables = _inventory(data.get("varnodes"), MAX_VARNODES, "varnodes")
    _require(bool(blocks), "pcode_no_blocks")
    entry = data.get("entry_block")
    _require(entry in blocks or (entry is None and not data["complete"]), "pcode_entry_invalid")
    for value in variables.values():
        _require(value.get("space") in spaces and value.get("kind") == spaces[value["space"]]["kind"], "pcode_varnode_space_invalid")
        _require(isinstance(value.get("offset"), str) and _HEX.fullmatch(value["offset"])
                 and _integer(value.get("size"), 1, 512), "pcode_varnode_storage_invalid")
        for key in ("input", "free"):
            _require(type(value.get(key)) is bool, "pcode_varnode_flags_invalid")
        for key in ("persistent", "unaffected", "addr_tied"):
            _require(type(value.get(key, False)) is bool, "pcode_varnode_flags_invalid")
        _require(value.get("definition") is None or value["definition"] in ops, "pcode_definition_missing")
        if value["kind"] == "constant":
            _require(value.get("definition") is None and not value["input"], "pcode_constant_defined")
        _require(not (value["input"] and value.get("definition") is not None), "pcode_input_redefined")
    owner, position, edges, seqs = {}, {}, [], set()
    for block in blocks.values():
        for key in ("start", "stop"):
            if block.get(key) is not None:
                canonical_address(block[key])
        for key in ("predecessors", "successors", "operations"):
            _require(isinstance(block.get(key), list), "pcode_block_inventory_invalid")
        _require(len(block["predecessors"]) <= MAX_EDGES and len(block["successors"]) <= MAX_EDGES, "pcode_edge_budget")
        for index, op_id in enumerate(block["operations"]):
            _require(isinstance(op_id, str) and op_id in ops and op_id not in owner, "pcode_operation_inventory_invalid")
            owner[op_id], position[op_id] = block["id"], index
        for slot, successor in enumerate(block["successors"]):
            _require(isinstance(successor, dict) and successor.get("block") in blocks
                     and _integer(successor.get("target_slot"), 0, MAX_EDGES), "pcode_successor_invalid")
            target = blocks[successor["block"]]
            _require(successor["target_slot"] < len(target.get("predecessors", [])), "pcode_edge_reverse_invalid")
            reverse = target["predecessors"][successor["target_slot"]]
            _require(reverse == {"block": block["id"], "source_slot": slot}, "pcode_edge_reverse_invalid")
            edges.append((block["id"], successor["block"]))
        for slot, predecessor in enumerate(block["predecessors"]):
            _require(isinstance(predecessor, dict) and predecessor.get("block") in blocks
                     and _integer(predecessor.get("source_slot"), 0, MAX_EDGES), "pcode_predecessor_invalid")
            source = blocks[predecessor["block"]]
            _require(predecessor["source_slot"] < len(source.get("successors", [])), "pcode_edge_reverse_invalid")
            reverse = source["successors"][predecessor["source_slot"]]
            _require(reverse == {"block": block["id"], "target_slot": slot}, "pcode_edge_reverse_invalid")
    _require(len(edges) <= MAX_EDGES and set(owner) == set(ops), "pcode_operation_or_edge_inventory_invalid")
    definitions, uses = {}, []
    effects = {key: [] for key in ("memory_read", "memory_write", "calls", "indirect_control", "unmodeled")}
    for op in ops.values():
        name = op.get("opcode")
        _require(isinstance(name, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name), "pcode_opcode_invalid")
        inputs, output = op.get("inputs"), op.get("output")
        _require(isinstance(inputs, list) and len(inputs) <= 512 and all(isinstance(v, str) and v in variables for v in inputs)
                 and (output is None or output in variables), "pcode_operand_missing")
        seq = op.get("sequence")
        _require(isinstance(seq, dict) and _integer(seq.get("time"), 0, 2**32-1)
                 and _integer(seq.get("order"), -(2**31), 2**31-1), "pcode_sequence_invalid")
        sequence = (canonical_address(seq.get("pc")), seq["time"])
        _require(sequence not in seqs, "pcode_sequence_duplicate")
        seqs.add(sequence)
        if output is not None:
            _require(output not in definitions and variables[output]["kind"] != "constant"
                     and variables[output].get("definition") == op["id"], "pcode_definition_disagreement")
            definitions[output] = op["id"]
        sizes = [variables[v]["size"] for v in inputs]
        width = variables[output]["size"] if output is not None else None
        if name in _BINARY | _COMPARE | _UNARY | {"MULTIEQUAL"}:
            count = 1 if name in _UNARY else 2
            _require(output is not None and ((bool(inputs)) if name == "MULTIEQUAL" else len(inputs) == count), "pcode_arity_invalid")
            if name in _COMPARE:
                _require(sizes[0] == sizes[1] and width == 1, "pcode_width_mismatch")
            else:
                _require(all(size == width for size in sizes), "pcode_width_mismatch")
        if name in {"INT_ZEXT", "INT_SEXT"}:
            _require(len(inputs) == 1 and width is not None and width > sizes[0], "pcode_extension_width_invalid")
        if name in {"INT_LEFT", "INT_RIGHT", "INT_SRIGHT"}:
            _require(len(inputs) == 2 and width == sizes[0], "pcode_shift_width_invalid")
        if name in {"BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR"}:
            _require(len(inputs) == (1 if name == "BOOL_NEGATE" else 2) and width == 1
                     and all(size == 1 for size in sizes), "pcode_boolean_shape_invalid")
        if name in {"POPCOUNT", "LZCOUNT"}:
            _require(len(inputs) == 1 and output is not None, "pcode_count_shape_invalid")
        if name == "PTRADD":
            _require(len(inputs) == 3 and width == sizes[0] and variables[inputs[2]]["kind"] == "constant", "pcode_ptradd_shape_invalid")
        if name == "PTRSUB":
            _require(len(inputs) == 2 and width == sizes[0], "pcode_ptrsub_shape_invalid")
        if name == "INDIRECT":
            _require(len(inputs) == 2 and output is not None and width == sizes[0], "pcode_indirect_shape_invalid")
        if name == "PIECE":
            _require(len(inputs) == 2 and width == sum(sizes), "pcode_piece_width_invalid")
        if name == "SUBPIECE":
            _require(len(inputs) == 2 and output is not None and variables[inputs[1]]["kind"] == "constant"
                     and int(variables[inputs[1]]["offset"], 16) + width <= sizes[0], "pcode_subpiece_invalid")
        if name == "LOAD":
            _require(len(inputs) == 2 and output is not None, "pcode_load_invalid")
            effects["memory_read"].append(op["id"])
        if name == "STORE":
            _require(len(inputs) == 3 and output is None, "pcode_store_invalid")
            effects["memory_write"].append(op["id"])
        if name in {"LOAD", "STORE"}:
            _require(variables[inputs[0]]["kind"] == "constant", "pcode_memory_space_not_constant")
            selector = int(variables[inputs[0]]["offset"],16)
            matching = [space for space in spaces.values() if (space["id"] & 0xffffffff) == selector]
            _require(len(matching) == 1 and sizes[1] == (matching[0]["bits"]+7)//8, "pcode_memory_space_or_pointer_invalid")
        if name in _CALLS:
            _require(bool(inputs), "pcode_call_invalid")
            effects["calls"].append(op["id"])
        if name in {"BRANCHIND", "CALLIND", "RETURN"}:
            _require(bool(inputs), "pcode_control_target_missing")
            # High P-Code hides the return address behind a constant marker.
            # The marker may be nonzero and smaller than a machine pointer.
            # Preserve it verbatim; dynamic targets still require pointer width.
            abstract_return = name == "RETURN" and variables[inputs[0]]["kind"] == "constant"
            pc_space = sequence[0].split(":",1)[0]
            _require(pc_space in spaces and (abstract_return or sizes[0] == (spaces[pc_space]["bits"]+7)//8), "pcode_control_pointer_width_invalid")
        if name in {"BRANCHIND", "CALLIND"}:
            effects["indirect_control"].append(op["id"])
        if name not in _KNOWN or name == "INDIRECT":
            effects["unmodeled"].append(op["id"])
        block = blocks[owner[op["id"]]]
        if name == "MULTIEQUAL":
            predecessors = [edge["block"] for edge in block["predecessors"]]
            _require(op.get("phi_predecessors") == predecessors and len(inputs) == len(predecessors), "pcode_phi_predecessor_mismatch")
        elif op.get("phi_predecessors"):
            raise ValueError("pcode_nonphi_predecessor_claim")
        for slot, variable in enumerate(inputs):
            metadata = slot == 0 and name in {"BRANCH", "CBRANCH", "CALL", "CALLOTHER", "LOAD", "STORE"} or slot == 1 and name == "INDIRECT"
            uses.append((op["id"], variable, slot, metadata))
    _require(all(value.get("definition") is None or definitions.get(value["id"]) == value["definition"] for value in variables.values()), "pcode_orphan_definition")
    for block in blocks.values():
        order = block["operations"]
        for index, identity in enumerate(order):
            if ops[identity]["opcode"] in _CONTROL:
                _require(index == len(order)-1 and ops[identity].get("output") is None, "pcode_control_position_invalid")
        last = ops[order[-1]]["opcode"] if order else None
        degree = len(block["successors"])
        _require(not data["complete"] or degree or order, "pcode_complete_empty_terminal")
        _require(degree <= 1 or last in {"CBRANCH", "BRANCHIND"}, "pcode_edges_without_control")
        _require(last == "CBRANCH" or not (block.get("true_out") is not None or block.get("false_out") is not None), "pcode_polarity_without_branch")
        if not degree and last in _KNOWN:
            _require(last in {"RETURN", "BRANCHIND"} | _CALLS, "pcode_terminal_without_control")
        if last == "CBRANCH":
            _require(len(block["successors"]) == 2 and len(ops[order[-1]]["inputs"]) == 2
                     and variables[ops[order[-1]]["inputs"][1]]["size"] == 1
                     and block.get("false_out") == block["successors"][0]["block"]
                     and block.get("true_out") == block["successors"][1]["block"], "pcode_branch_polarity_invalid")
        if last == "RETURN":
            _require(not block["successors"] and bool(ops[order[-1]]["inputs"]), "pcode_return_successor_invalid")
        if last == "BRANCH":
            _require(len(block["successors"]) == 1 and len(ops[order[-1]]["inputs"]) == 1, "pcode_branch_successor_invalid")
        if last == "BRANCHIND":
            _require(len(ops[order[-1]]["inputs"]) == 1, "pcode_indirect_branch_arity_invalid")
    reachable, pending = set(), [entry] if entry is not None else []
    while pending:
        block = pending.pop()
        if block not in reachable:
            reachable.add(block)
            pending.extend(edge["block"] for edge in blocks[block]["successors"])
    active = [node for node in blocks if node in reachable]
    idom = compute_immediate_dominators_pure(active, [(s,t) for s,t in edges if s in reachable], entry) if entry is not None else {}
    unresolved = set()
    for op_id, variable, slot, metadata in uses:
        value, op = variables[variable], ops[op_id]
        if metadata or value["kind"] == "constant":
            continue
        definition = value.get("definition")
        if definition is None:
            if not value["input"]:
                unresolved.add(variable)
            continue
        use_block, def_block = owner[op_id], owner[definition]
        if op["opcode"] == "MULTIEQUAL":
            use_block = op["phi_predecessors"][slot]
        elif use_block == def_block:
            _require(position[definition] < position[op_id], "pcode_use_before_definition")
        if use_block in reachable:
            _require(def_block in reachable and _dominates(def_block, use_block, idom), "pcode_definition_does_not_dominate")
    losses = ["decompiler High P-Code is inferred, not original source or binary equivalence", "types, ABI, memory aliasing and original flag state are not proved", "confidence is not calibrated"]
    if unresolved:
        losses.append("nonconstant live-ins without an input declaration remain unresolved")
    function_id = expected_target + "!" + address
    references = ("sha256:" + evidence_sha256, "sha256:" + expected_target)
    nodes, graph_edges, identities = [], [], {}
    def add_node(kind, identity, attributes):
        node = IRNode("pcode-"+kind, identity, IRLocation("ghidra-high-pcode", function_id+"/"+kind+"/"+identity, expected_target),
                      "ghidra-high-pcode", references, EpistemicState.PROBABILISTIC_INFERENCE, 0.0, tuple(losses), attributes)
        nodes.append(node)
        identities[kind, identity] = node.identity
    def edge(kind, source, target, attributes=None):
        graph_edges.append(IREdge(kind, identities[source], identities[target], "ghidra-high-pcode", references,
                                  EpistemicState.PROBABILISTIC_INFERENCE, 0.0, tuple(losses), attributes or {}))
    for identity, block in blocks.items():
        add_node("block", identity, {**block, "reachable": identity in reachable})
    for identity, op in ops.items():
        add_node("operation", identity, op)
    for identity, variable in variables.items():
        add_node("varnode", identity, variable)
    for identity, block in blocks.items():
        for slot, successor in enumerate(block["successors"]):
            edge("cfg", ("block",identity),("block",successor["block"]), {"source_slot":slot,"target_slot":successor["target_slot"]})
        for op in block["operations"]:
            edge("contains",("block",identity),("operation",op),{"position":position[op]})
    for variable, op in definitions.items():
        edge("definition",("operation",op),("varnode",variable))
    for op, variable, slot, metadata in uses:
        attributes = {"slot":slot,"role":"control_or_metadata" if metadata else "value"}
        if ops[op]["opcode"] == "MULTIEQUAL":
            attributes["predecessor"] = ops[op]["phi_predecessors"][slot]
        edge("operand",("varnode",variable),("operation",op),attributes)
    graph = canonical_ir_dict(IRDocument("ir.v1", "sha256:"+expected_target, "native-high-pcode", tuple(nodes), tuple(graph_edges), tuple(losses)))
    graph["context"] = context
    graph["function_id"] = function_id
    summary = dict(status="structurally_valid" if data["complete"] and entry is not None else "partial",blocks=len(blocks),operations=len(ops),varnodes=len(variables),
                   cfg_edges=len(edges),phi_operations=sum(op["opcode"]=="MULTIEQUAL" for op in ops.values()),
                   dominance_checked=entry is not None,unreachable_blocks=sorted(set(blocks)-reachable),unresolved_liveins=sorted(unresolved),
                   effects=effects,semantic_equivalence_proved=False,binary_semantics_recovered=False,original_source_recovered=False,
                   source_ir_sha256=evidence_sha256,limitations=losses)
    return {"summary":summary,"graph":graph}
