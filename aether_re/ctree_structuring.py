"""C control-flow restructuring from an explicit, syntax-checked C CFG.

This transforms supplied predicates/effects, never infers them from block
names. Unrecognized regions retain labels and transfers. Syntax checking
is not type checking, binary equivalence, or recovery of original source.
"""
from __future__ import annotations

from collections import deque
import re
import threading
from typing import Any, Sequence

from aether_re.cfg_dominance import compute_immediate_dominators_pure, find_natural_loops

_C_PARSER_TLS = threading.local()


def _get_shared_c_parser():
    from pycparser import c_parser

    parser = getattr(_C_PARSER_TLS, "parser", None)
    if parser is None:
        parser = c_parser.CParser()
        _C_PARSER_TLS.parser = parser
    return parser

SCHEMA = "ctree-structuring-report.v2"
_EXIT = object()
_C_STRING = r'(?:u8|[uUL])?"(?:\\.|[^"\\])*"'
_C_CHAR = r"(?:[uUL])?'(?:\\.|[^'\\])*'"
_C_LITERALS = _C_STRING + "|" + _C_CHAR
_C_TOKENS = re.compile(_C_LITERALS + r"|/\*.*?\*/|//[^\n]*", re.S)
_TRIGRAPHS = dict(zip("=/\u0027()!<>-", "#\\^[]|{}~"))


def _escape_literal_questions(token):
    # Prevent a second translation unit from interpreting a newly formed
    # trigraph. Keep existing escape pairs, including \\?, byte-for-byte.
    result, index = [], 0
    while index < len(token):
        char = token[index]
        if char == "\\" and index + 1 < len(token):
            result.append(token[index:index + 2])
            index += 2
        else:
            result.append("\\?" if char == "?" else char)
            index += 1
    return "".join(result)


class _Incomplete(ValueError):
    pass


class _NotStructured(ValueError):
    pass


def _walk_tree(tree):
    for node in tree:
        yield node
        for key in ("then", "else", "body"):
            yield from _walk_tree(node.get(key, []))
        for arm in node.get("arms", []):
            yield from _walk_tree(arm["body"])


def _render(tree, indent=1):
    lines = []
    pad = "    " * indent
    for node in tree:
        kind = node["kind"]
        if kind == "block":
            lines.extend(pad + statement for statement in node["statements"])
        elif kind == "label":
            lines.append(pad + node["name"] + ":")
        elif kind == "goto":
            lines.append(pad + "goto " + node["target"] + ";")
        elif kind == "return":
            lines.append(pad + "return" + (" " + node["value"] if node["value"] is not None else "") + ";")
        elif kind in {"break", "continue"}:
            lines.append(pad + kind + ";")
        elif kind == "if":
            lines.append(pad + "if (" + node["condition"] + ") {")
            lines.extend(_render(node["then"], indent + 1))
            if node["else"]:
                lines.append(pad + "} else {")
                lines.extend(_render(node["else"], indent + 1))
            lines.append(pad + "}")
        elif kind == "while":
            lines.append(pad + "while (1) {")
            lines.extend(_render(node["body"], indent + 1))
            lines.append(pad + "}")
        elif kind == "switch":
            lines.append(pad + "switch (" + node["expression"] + ") {")
            for arm in node["arms"]:
                for value in arm["labels"]:
                    lines.append(pad + ("default:" if value is None else f"case {value}:"))
                lines.extend(_render(arm["body"], indent + 1))
            lines.append(pad + "}")
        else:
            raise ValueError("unknown_ctree_node")
    return lines


def _dominates(header, node, idoms):
    while node is not None:
        if header == node:
            return True
        parent = idoms[node]
        if parent == node:
            break
        node = parent
    return False


def _is_reducible(nodes, edges, idoms):
    # A flow graph is reducible iff removing all dominance backedges
    # leaves an acyclic graph. This detects cycles with no natural header.
    remaining = [(s, t) for s, t in edges if not _dominates(t, s, idoms)]
    outgoing = {n: [] for n in nodes}
    indegree = {n: 0 for n in nodes}
    for source, target in remaining:
        outgoing[source].append(target)
        indegree[target] += 1
    ready = deque(sorted(n for n in nodes if not indegree[n]))
    removed = 0
    while ready:
        source = ready.popleft()
        removed += 1
        for target in outgoing[source]:
            indegree[target] -= 1
            if not indegree[target]:
                ready.append(target)
    return removed == len(nodes)


def _postdominators(nodes, successors):
    predecessors = {n: [] for n in nodes}
    terminal = [n for n in nodes if not successors[n]]
    for source in nodes:
        for target in successors[source]:
            predecessors[target].append(source)
    exitable, pending = set(), list(terminal)
    while pending:
        node = pending.pop()
        if node not in exitable:
            exitable.add(node)
            pending.extend(predecessors[node])
    if exitable != set(nodes):
        raise _NotStructured("region_without_exit_retained_explicitly")
    universe = set(nodes) | {_EXIT}
    pdom = {n: set(universe) for n in nodes}
    pdom[_EXIT] = {_EXIT}
    changed = True
    while changed:
        changed = False
        for node in reversed(nodes):
            children = successors[node] or [_EXIT]
            refined = {node} | set.intersection(*(pdom[c] for c in children))
            if refined != pdom[node]:
                pdom[node] = refined
                changed = True
    return {n: max(pdom[n] - {n}, key=lambda item: len(pdom[item])) for n in nodes}


class _Regions:
    def __init__(self, nodes, edges, semantics, entry, loop_nodes):
        self.nodes = nodes
        self.semantics = semantics
        self.successors = {n: [] for n in nodes}
        for source, target in edges:
            self.successors[source].append(target)
        self.postdom = _postdominators(nodes, self.successors)
        self.loops = loop_nodes
        self.visited = set()
        self.entry = entry

    def block(self, name):
        if name in self.visited:
            raise _NotStructured("shared_region_requires_explicit_transfer")
        self.visited.add(name)
        return {"kind": "block", "block": name, "statements": self.semantics[name]["statements"]}

    @staticmethod
    def boundary(target, context):
        if context and target == context[0]:
            return [{"kind": "continue"}]
        if context and target == context[1]:
            return [{"kind": "break"}]
        return None

    def emit(self, start, stop, allowed, context=None, depth=0):
        if depth > 128:
            raise _NotStructured("region_depth_budget")
        result, current = [], start
        while current != stop and current is not _EXIT:
            transfer = self.boundary(current, context)
            if transfer is not None:
                return result + transfer
            if current not in allowed:
                raise _NotStructured("region_crosses_boundary")
            if current in self.loops:
                members = self.loops[current]
                term = self.semantics[current]["terminator"]
                if term["kind"] != "branch" or not members <= allowed:
                    raise _NotStructured("loop_header_not_a_two_way_test")
                inside_true = term["true"] in members
                if inside_true == (term["false"] in members):
                    raise _NotStructured("loop_header_has_no_unique_exit")
                inside = term["true"] if inside_true else term["false"]
                outside = term["false"] if inside_true else term["true"]
                if any(target not in members and target != outside for source in members for target in self.successors[source]):
                    raise _NotStructured("multiple_loop_exit_targets")
                header = self.block(current)
                before = set(self.visited)
                body = self.emit(inside, current, members - {current}, (current, outside), depth + 1)
                if self.visited - before != members - {current}:
                    raise _NotStructured("loop_region_inventory_mismatch")
                exit_condition = "!(" + term["condition"] + ")" if inside_true else term["condition"]
                result.append({"kind": "while", "header": current, "body": [header,
                    {"kind": "if", "condition": exit_condition, "then": [{"kind": "break"}], "else": []}, *body]})
                current = outside
                continue
            result.append(self.block(current))
            term = self.semantics[current]["terminator"]
            kind = term["kind"]
            if kind == "return":
                return result + [{"kind": "return", "value": term["value"]}]
            if kind == "jump":
                current = term["target"]
                continue
            if kind == "branch":
                if context and any(self.boundary(term[key], context) is not None for key in ("true", "false")):
                    branches = []
                    for key in ("true", "false"):
                        direct = self.boundary(term[key], context)
                        branches.append(direct if direct is not None else self.emit(term[key], stop, allowed, context, depth + 1))
                    return result + [{"kind": "if", "condition": term["condition"], "then": branches[0], "else": branches[1]}]
                join = self.postdom[current]
                if join not in allowed and join != stop and join is not _EXIT:
                    raise _NotStructured("conditional_join_outside_region")
                yes = self.emit(term["true"], join, allowed, context, depth + 1)
                no = self.emit(term["false"], join, allowed, context, depth + 1)
                result.append({"kind": "if", "condition": term["condition"], "then": yes, "else": no})
                current = join
                continue
            if kind == "switch":
                if context:
                    raise _NotStructured("switch_inside_loop_retains_explicit_transfers")
                join = self.postdom[current]
                groups = {}
                for case in term["cases"]:
                    groups.setdefault(case["target"], []).append(case["value"])
                groups.setdefault(term["default"], []).append(None)
                arms = []
                for target, labels in groups.items():
                    body = self.emit(target, join, allowed, context, depth + 1)
                    arms.append({"labels": labels, "body": [*body, {"kind": "break"}]})
                result.append({"kind": "switch", "expression": term["expression"], "arms": arms})
                current = join
                continue
            raise _NotStructured("unsupported_region_terminator")
        return result


def structure_control_flow(nodes: Sequence[str], edges: Sequence[tuple[str, str]],
                           idom: dict[str, str | None], natural_loops: Sequence[dict[str, Any]],
                           entry: str, *, block_semantics: dict[str, Any] | None = None,
                           function_signature: str | None = None,
                           declarations: Sequence[str] = (), node_budget: int = 256) -> dict[str, Any]:
    """Transform a provided C CFG, retaining explicit flow when needed.

    statements are single C expression statements; declarations are function
    scoped. Terminators are return/jump/branch/switch and must match edges.
    Analysis hints are checked against recomputation, never trusted blindly.
    No compiler, binary or generated source is executed by this function.
    """
    report = dict(schema=SCHEMA, status="invalid", entry_point=entry,
                  total_nodes=0, total_edges=0, natural_loops_structured=0,
                  raw_gotos_estimated=None, raw_gotos_count=None, gotos_remaining=None,
                  goto_elimination_rate_pct=None, structured_c_source=None, ctree=None,
                  strategy=None, is_reducible=None, unreachable_blocks=[], emitted_blocks=[],
                  analysis_hints_verified=None, c_syntax_checked=False, c_type_checked=False,
                  compile_verified=False, semantic_equivalence_proved=False,
                  preservation_scope="provided_c_cfg", binary_semantics_recovered=False,
                  c_translation_model="c11_phase1_trigraphs_phase2_splicing_no_directives",
                  errors=[], limitations=["provided C semantics only; not original source or binary equivalence",
                      "C parser checks syntax; types, ABI, undefined behavior and external effects are not proved"])
    try:
        if type(node_budget) is not int or not 256 <= node_budget <= 512:
            raise ValueError("invalid_node_budget")
        if node_budget != 256:
            report['node_budget'] = node_budget
        if (not isinstance(nodes, (list, tuple)) or not 1 <= len(nodes) <= node_budget
                or any(not isinstance(n, str) or not n or len(n) > 128 for n in nodes)
                or len(set(nodes)) != len(nodes) or entry not in nodes):
            raise ValueError("invalid_nodes_or_node_budget")
        if not isinstance(edges, (list, tuple)) or len(edges) > 2048:
            raise ValueError("invalid_edges_or_edge_budget")
        if not isinstance(idom, dict) or not isinstance(natural_loops, (list, tuple)) or len(natural_loops) > 1024:
            raise ValueError("invalid_analysis_hints")
        node_set = set(nodes)
        edge_set = set()
        for edge in edges:
            if (not isinstance(edge, (list, tuple)) or len(edge) != 2
                    or any(not isinstance(n, str) or n not in node_set for n in edge)):
                raise ValueError("edge_endpoint_not_declared")
            edge_set.add(tuple(edge))
        successors = {n: set() for n in nodes}
        for source, target in edge_set:
            successors[source].add(target)
        reachable, pending = set(), [entry]
        while pending:
            node = pending.pop()
            if node not in reachable:
                reachable.add(node)
                pending.extend(successors[node])
        ordered = [entry, *sorted(reachable - {entry})]
        active_edges = sorted((s, t) for s, t in edge_set if s in reachable)
        report.update(total_nodes=len(nodes), total_edges=len(edge_set), unreachable_blocks=sorted(node_set-reachable))
        actual_idom = compute_immediate_dominators_pure(ordered, active_edges, entry)
        loops = find_natural_loops(ordered, active_edges, actual_idom)
        loop_nodes = {}
        for loop in loops:
            loop_nodes.setdefault(loop["header"], set()).update(loop["nodes"])
        hint_loops = {}
        for loop in natural_loops:
            if not isinstance(loop, dict) or not isinstance(loop.get("header"), str) or not isinstance(loop.get("nodes"), (list, tuple)):
                raise ValueError("invalid_loop_hint")
            hint_loops.setdefault(loop["header"], set()).update(loop["nodes"])
        if idom or natural_loops:
            normalized = {n: entry if n == entry and p is None else p for n, p in idom.items()}
            report["analysis_hints_verified"] = normalized == actual_idom and hint_loops == loop_nodes
        report.update(is_reducible=_is_reducible(ordered, active_edges, actual_idom),
                      immediate_dominators=actual_idom, analysis_recomputed=True,
                      natural_loops_detected=len(loop_nodes))
        if block_semantics is None or function_signature is None:
            raise _Incomplete("effects_predicates_and_function_context_required")
        if not isinstance(block_semantics, dict):
            raise ValueError("invalid_block_semantics")
        if not reachable <= block_semantics.keys():
            raise _Incomplete("reachable_block_semantics_missing")
        if set(block_semantics)-node_set:
            raise ValueError("semantics_for_undeclared_block")
        from pycparser import c_ast, c_generator
        parser = _get_shared_c_parser()
        literal_tokens = {}

        class LiteralPreservingGenerator(c_generator.CGenerator):
            def visit_Constant(self, node):
                if node.type == "string":
                    # pycparser concatenates adjacent literal contents, which
                    # changes hex/octal escape boundaries if emitted as one
                    # token. Parse opaque markers and restore separate tokens.
                    match = re.fullmatch(r'(?:u8|[uUL])?"((?:__aether_ct_lit_\d+__)+)"', node.value)
                    if match is None:
                        raise ValueError("unpreserved_string_literal")
                    markers = re.findall(r"__aether_ct_lit_\d+__", match[1])
                    if any(marker not in literal_tokens for marker in markers):
                        raise ValueError("unknown_string_literal_marker")
                    return " ".join(_escape_literal_questions(literal_tokens[marker]) for marker in markers)
                return _escape_literal_questions(super().visit_Constant(node))

        generator = LiteralPreservingGenerator()
        character_count, statement_count, ast_count = 0, 0, 0
        scope_sensitive = False

        def text(value):
            nonlocal character_count
            if not isinstance(value, str) or not value.strip() or len(value) > 4096:
                raise ValueError("invalid_or_oversized_c_fragment")
            character_count += len(value)
            if character_count > 1024*1024:
                raise ValueError("c_fragment_budget_exceeded")
            # C11 phase 1 precedes phase 2. Do this exactly once per supplied
            # fragment: splicing itself may form a sequence resembling a
            # trigraph that must NOT undergo another phase-1 conversion.
            physical = value.replace("\r\n", "\n").replace("\r", "\n")
            phase1 = re.sub(r"\?\?([=/\u0027()!<>-])", lambda match: _TRIGRAPHS[match[1]], physical)
            spliced = re.sub(r"\\(?:\r\n|\n|\r)", "", phase1)
            cleaned = _C_TOKENS.sub(lambda match: " " if match[0].startswith(("/*", "//")) else match[0], spliced)
            if "#" in re.sub(_C_LITERALS, "", cleaned):
                raise ValueError("preprocessor_directives_not_supported")

            def preserve_literal(match):
                token = match[0]
                if not re.fullmatch(_C_STRING, token, re.S):
                    return token
                if len(literal_tokens) >= 8192:
                    raise ValueError("string_literal_budget_exceeded")
                marker = f"__aether_ct_lit_{len(literal_tokens)}__"
                literal_tokens[marker] = token
                prefix = token[:token.index('"')]
                return prefix + '"' + marker + '"'

            return _C_TOKENS.sub(preserve_literal, cleaned)

        def _count_ast_items(items: Sequence[Any]) -> None:
            nonlocal ast_count, scope_sensitive
            pending_ast = list(items)
            while pending_ast:
                current = pending_ast.pop()
                ast_count += 1
                if ast_count > 100000:
                    raise ValueError("c_ast_budget_exceeded")
                if isinstance(current, c_ast.CompoundLiteral):
                    scope_sensitive = True
                pending_ast.extend(child for _, child in current.children())

        def one_body(fragment, *, prepared=False):
            nonlocal ast_count, scope_sensitive
            tree = parser.parse("void __aether_probe(void){" + (fragment if prepared else text(fragment)) + "}")
            if len(tree.ext) != 1 or not isinstance(tree.ext[0], c_ast.FuncDef):
                raise ValueError("fragment_escapes_function")
            pending = [tree]
            while pending:
                current = pending.pop()
                ast_count += 1
                if ast_count > 100000:
                    raise ValueError("c_ast_budget_exceeded")
                if isinstance(current, c_ast.CompoundLiteral):
                    scope_sensitive = True
                pending.extend(child for _, child in current.children())
            return tree.ext[0].body.block_items or []

        def expression(value, *, prepared=False):
            raw_expr = value if prepared else text(value)
            items = one_body("__aether_expr = (" + raw_expr + ");", prepared=True)
            if len(items) != 1 or not isinstance(items[0], c_ast.Assignment) or not isinstance(items[0].lvalue, c_ast.ID) or items[0].lvalue.name != "__aether_expr":
                raise ValueError("expression_contains_statements")
            return generator.visit(items[0].rvalue)

        signature_tree = parser.parse(text(function_signature) + "{}")
        if len(signature_tree.ext) != 1 or not isinstance(signature_tree.ext[0], c_ast.FuncDef):
            raise ValueError("single_function_signature_required")
        function = signature_tree.ext[0]
        if function.decl.funcspec and any(s != "inline" for s in function.decl.funcspec):
            raise ValueError("unmodeled_function_specifier")
        signature = generator.visit(function.decl)
        return_type = function.decl.type.type
        returns_void = isinstance(return_type, c_ast.TypeDecl) and isinstance(return_type.type, c_ast.IdentifierType) and return_type.type.names == ["void"]
        if not isinstance(declarations, (list, tuple)) or len(declarations) > 1024:
            raise ValueError("invalid_declarations")

        # Validate structure and prepare fragments up front so valid CFGs can parse in a single TU batch.
        prep_decls = [text(d) for d in declarations]
        prep_blocks: list[tuple[str, list[str], dict[str, Any], set[str], str | None]] = []
        for node in ordered:
            raw = block_semantics[node]
            if not isinstance(raw, dict) or set(raw) - {"statements", "terminator"}:
                raise ValueError("invalid_block_semantics_fields")
            statements = raw.get("statements", [])
            term = raw.get("terminator")
            if term is None:
                raise _Incomplete("block_terminator_missing")
            if not isinstance(statements, (list, tuple)) or not isinstance(term, dict):
                raise ValueError("invalid_statements_or_terminator")
            prep_stmts = []
            for statement in statements:
                statement_count += 1
                if statement_count > 4096:
                    raise ValueError("statement_budget_exceeded")
                prep_stmts.append(text(statement))
            kind = term.get("kind")
            prep_term_expr: str | None = None
            if kind == "return":
                if set(term) - {"kind", "value"}:
                    raise ValueError("unknown_return_fields")
                value = term.get("value")
                if returns_void != (value is None):
                    raise ValueError("return_value_signature_mismatch")
                if value is not None:
                    prep_term_expr = text(value)
                targets = set()
            elif kind == "jump":
                if set(term) != {"kind", "target"}:
                    raise ValueError("invalid_jump_fields")
                targets = {term["target"]}
            elif kind == "branch":
                if set(term) != {"kind", "condition", "true", "false"}:
                    raise ValueError("branch_predicate_and_polarity_required")
                prep_term_expr = text(term["condition"])
                targets = {term["true"], term["false"]}
            elif kind == "switch":
                if set(term) != {"kind", "expression", "cases", "default"} or not isinstance(term["cases"], (list, tuple)) or len(term["cases"]) > 1024:
                    raise ValueError("invalid_switch_fields")
                values = set()
                for case in term["cases"]:
                    if not isinstance(case, dict) or set(case) != {"value", "target"} or type(case["value"]) is not int or not -(2**31) <= case["value"] < 2**31 or case["value"] in values:
                        raise ValueError("invalid_or_duplicate_switch_case")
                    values.add(case["value"])
                prep_term_expr = text(term["expression"])
                targets = {term["default"], *(case["target"] for case in term["cases"])}
            else:
                raise ValueError("unsupported_terminator")
            if any(not isinstance(target, str) for target in targets) or targets != successors[node]:
                raise ValueError("terminator_cfg_disagreement")
            prep_blocks.append((node, prep_stmts, term, targets, prep_term_expr))

        # Single-TU batch parse with sentinel markers; falls back seamlessly on any anomaly.
        batch_slices: dict[int, list[Any]] | None = None
        batch_fragments: list[str] = list(prep_decls)
        stmt_slot_map: dict[tuple[int, int], int] = {}
        term_slot_map: dict[int, int] = {}
        for b_idx, (_, p_stmts, _term, _tgts, p_term_expr) in enumerate(prep_blocks):
            for s_idx, p_st in enumerate(p_stmts):
                stmt_slot_map[(b_idx, s_idx)] = len(batch_fragments)
                batch_fragments.append(p_st)
            if p_term_expr is not None:
                term_slot_map[b_idx] = len(batch_fragments)
                batch_fragments.append("__aether_expr = (" + p_term_expr + ");")

        if batch_fragments:
            try:
                chunks = ["void __aether_batch(void){"]
                for idx_f, frag in enumerate(batch_fragments):
                    chunks.append(f"__aether_bmark({idx_f});")
                    chunks.append(frag)
                chunks.append(f"__aether_bmark({len(batch_fragments)});")
                chunks.append("}")
                batch_tree = parser.parse("\n".join(chunks))
                if (
                    len(batch_tree.ext) == 1
                    and isinstance(batch_tree.ext[0], c_ast.FuncDef)
                    and batch_tree.ext[0].decl.name == "__aether_batch"
                ):
                    body_items = batch_tree.ext[0].body.block_items or []
                    parsed_map: dict[int, list[Any]] = {}
                    cur_idx: int | None = None
                    cur_bucket: list[Any] = []
                    expected_idx = 0
                    sentinel_ok = True
                    for item in body_items:
                        if (
                            isinstance(item, c_ast.FuncCall)
                            and isinstance(item.name, c_ast.ID)
                            and item.name.name == "__aether_bmark"
                            and item.args
                            and len(item.args.exprs) == 1
                            and isinstance(item.args.exprs[0], c_ast.Constant)
                            and item.args.exprs[0].type == "int"
                        ):
                            mark_id = int(item.args.exprs[0].value, 0)
                            if mark_id != expected_idx:
                                sentinel_ok = False
                                break
                            if cur_idx is not None:
                                parsed_map[cur_idx] = cur_bucket
                            cur_idx = mark_id
                            cur_bucket = []
                            expected_idx += 1
                        else:
                            if cur_idx is None:
                                sentinel_ok = False
                                break
                            cur_bucket.append(item)
                    if sentinel_ok and expected_idx == len(batch_fragments) + 1 and len(parsed_map) == len(batch_fragments):
                        batch_slices = parsed_map
            except Exception:
                batch_slices = None

        def _get_parsed(slot_idx: int, raw_frag: str, *, is_expr: bool = False) -> list[Any]:
            if batch_slices is not None and slot_idx in batch_slices:
                items = batch_slices[slot_idx]
                ast_count_overhead = 4  # matches FuncDef + Compound + ParamList baseline in one_body
                nonlocal ast_count
                ast_count += ast_count_overhead
                if ast_count > 100000:
                    raise ValueError("c_ast_budget_exceeded")
                _count_ast_items(items)
                return items
            return one_body(("__aether_expr = (" + raw_frag + ");") if is_expr else raw_frag, prepared=True)

        local_declarations = []
        for d_idx, prep_decl in enumerate(prep_decls):
            items = _get_parsed(d_idx, prep_decl)
            if len(items) != 1 or not isinstance(items[0], c_ast.Decl):
                raise ValueError("function_scope_declaration_required")
            local_declarations.append(generator.visit(items[0]) + ";")

        semantics = {}
        for b_idx, (node, prep_stmts, term, _targets, prep_term_expr) in enumerate(prep_blocks):
            canonical = []
            for s_idx, prep_stmt in enumerate(prep_stmts):
                items = _get_parsed(stmt_slot_map[(b_idx, s_idx)], prep_stmt)
                if not items:
                    continue  # A comment-only fragment has no C effect.
                if len(items) != 1 or not isinstance(items[0], (c_ast.Assignment, c_ast.FuncCall, c_ast.UnaryOp, c_ast.ExprList, c_ast.EmptyStatement)):
                    raise ValueError("only_expression_statements_allowed_in_block")
                code = generator.visit(items[0]).rstrip()
                canonical.append(code if code.endswith(";") else code + ";")
            kind = term["kind"]
            normalized = {"kind": kind}
            if kind == "return":
                if prep_term_expr is not None:
                    e_items = _get_parsed(term_slot_map[b_idx], prep_term_expr, is_expr=True)
                    if len(e_items) != 1 or not isinstance(e_items[0], c_ast.Assignment) or not isinstance(e_items[0].lvalue, c_ast.ID) or e_items[0].lvalue.name != "__aether_expr":
                        raise ValueError("expression_contains_statements")
                    normalized["value"] = generator.visit(e_items[0].rvalue)
                else:
                    normalized["value"] = None
            elif kind == "jump":
                normalized["target"] = term["target"]
            elif kind == "branch":
                e_items = _get_parsed(term_slot_map[b_idx], prep_term_expr or "", is_expr=True)
                if len(e_items) != 1 or not isinstance(e_items[0], c_ast.Assignment) or not isinstance(e_items[0].lvalue, c_ast.ID) or e_items[0].lvalue.name != "__aether_expr":
                    raise ValueError("expression_contains_statements")
                normalized.update(condition=generator.visit(e_items[0].rvalue), **{"true": term["true"], "false": term["false"]})
            elif kind == "switch":
                e_items = _get_parsed(term_slot_map[b_idx], prep_term_expr or "", is_expr=True)
                if len(e_items) != 1 or not isinstance(e_items[0], c_ast.Assignment) or not isinstance(e_items[0].lvalue, c_ast.ID) or e_items[0].lvalue.name != "__aether_expr":
                    raise ValueError("expression_contains_statements")
                normalized.update(expression=generator.visit(e_items[0].rvalue), cases=[dict(c) for c in term["cases"]], default=term["default"])
            semantics[node] = {"statements": canonical, "terminator": normalized}

        labels = {node: f"aether_bb_{index}" for index, node in enumerate(ordered)}
        jump = lambda target: {"kind": "goto", "target": labels[target]}
        explicit = [jump(entry)]
        for node in ordered:
            explicit.extend([{"kind": "label", "name": labels[node]},
                             {"kind": "block", "block": node, "statements": semantics[node]["statements"]}])
            term = semantics[node]["terminator"]
            if term["kind"] == "return":
                explicit.append({"kind": "return", "value": term["value"]})
            elif term["kind"] == "jump":
                explicit.append(jump(term["target"]))
            elif term["kind"] == "branch":
                explicit.append({"kind": "if", "condition": term["condition"], "then": [jump(term["true"])], "else": [jump(term["false"])]})
            else:
                arms = [{"labels": [case["value"]], "body": [jump(case["target"])]} for case in term["cases"]]
                arms.append({"labels": [None], "body": [jump(term["default"])]})
                explicit.append({"kind": "switch", "expression": term["expression"], "arms": arms})
        strategy, reason = "structured_regions", None
        try:
            if scope_sensitive:
                raise _NotStructured("scope_sensitive_c_requires_explicit_cfg")
            if not report["is_reducible"]:
                raise _NotStructured("irreducible_cfg_retains_explicit_transfers")
            regions = _Regions(ordered, active_edges, semantics, entry, loop_nodes)
            ctree = regions.emit(entry, _EXIT, set(ordered))
            if regions.visited != reachable:
                raise _NotStructured("structured_region_inventory_mismatch")
        except _NotStructured as exc:
            strategy, reason, ctree = "explicit_cfg", str(exc), explicit
        source = signature + "\n{\n" + "\n".join([*("    " + d for d in local_declarations), *_render(ctree)]) + "\n}\n"
        if len(source) > 2*1024*1024:
            raise ValueError("generated_source_budget_exceeded")
        parser.parse(source)
        items = list(_walk_tree(ctree))
        emitted = [item["block"] for item in items if item["kind"] == "block"]
        if len(emitted) != len(reachable) or set(emitted) != reachable:
            raise ValueError("emitted_block_inventory_mismatch")
        raw_gotos = sum(item["kind"] == "goto" for item in _walk_tree(explicit))
        gotos = sum(item["kind"] == "goto" for item in items)
        report.update(status="complete", strategy=strategy, fallback_reason=reason, ctree=ctree,
                      structured_c_source=source, c_syntax_checked=True, emitted_blocks=emitted,
                      natural_loops_structured=sum(item["kind"] == "while" for item in items),
                      raw_gotos_count=raw_gotos, gotos_remaining=gotos,
                      goto_elimination_rate_pct=round(100*(raw_gotos-gotos)/raw_gotos, 2) if raw_gotos else None)
    except _Incomplete as exc:
        report.update(status="incomplete", errors=[str(exc)])
    except (ValueError, TypeError, KeyError, RecursionError, ImportError) as exc:
        report["errors"] = [str(exc)[:240] or type(exc).__name__]
    except Exception as exc:
        # Parsing unsupported C syntax abstains without publishing any source.
        report["errors"] = [type(exc).__name__ + ":" + str(exc)[:200]]
    return report
