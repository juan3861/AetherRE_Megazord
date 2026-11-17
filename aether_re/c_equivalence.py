"""Static counterexample search for pure C integer functions.

This is an explicitly modeled comparison, not binary equivalence. Supported
functions have 32-bit int/unsigned parameters, locals, branches and returns.
Memory, calls, loops, globals, volatile and unsupported types abstain. Signed
overflow/division UB is tracked: a candidate must preserve every input on
which the reference is defined. No target or compiler is executed.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


class _Unsupported(ValueError):
    pass


def compare_c_functions(reference: str, candidate: str, name: str, *, timeout_ms: int = 1000) -> dict[str, Any]:
    result = {
        "schema": "c-behavioral-comparison.v1", "status": "unknown",
        "model": "c_integer32_pure_functions", "universal_proof": False,
        "target_executed": False, "counterexample": None,
        "reference_sha256": hashlib.sha256(reference.encode()).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
        "assumptions": ["int and unsigned int are 32 bits", "two's-complement integer conversions",
                        "C11 signed left shift rules; signed right shift is arithmetic",
                        "reference-defined inputs only", "pure scalar functions; no memory or external effects"],
    }
    try:
        import z3
        from pycparser import c_ast, c_parser
    except ImportError:
        result["reason"] = "pycparser_or_z3_unavailable"
        return result
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000:
        result["reason"] = "invalid_solver_budget"
        return result

    @dataclass
    class Value:
        bits: Any
        unsigned: bool
        defined: Any

    def value(bits, unsigned=False, defined=None):
        return Value(bits, unsigned, z3.BoolVal(True) if defined is None else defined)

    def ctype(node):
        if not isinstance(node, c_ast.TypeDecl) or node.quals:
            raise _Unsupported("unsupported_type_or_qualifier")
        if not isinstance(node.type, c_ast.IdentifierType):
            raise _Unsupported("unsupported_type")
        names = tuple(node.type.names)
        if names in (("int",), ("signed",), ("signed", "int")):
            return False
        if names in (("unsigned",), ("unsigned", "int")):
            return True
        raise _Unsupported("unsupported_integer_width")

    def parse(text, allow_single=False):
        if len(text) > 65536:
            raise _Unsupported("source_budget_exceeded")
        # Preserve strings/chars while removing comments; never preprocess or
        # execute directives supplied by an analyzed source.
        tokens = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*'
        text = re.sub(tokens, lambda m: " " if m[0].startswith(("/*", "//")) else m[0], text, flags=re.S)
        tree = c_parser.CParser().parse(text)
        functions = [n for n in tree.ext if isinstance(n, c_ast.FuncDef)]
        selected = [f for f in functions if f.decl.name == name]
        if not selected and allow_single and len(functions) == 1:
            selected = functions
        if len(selected) != 1:
            raise _Unsupported("function_not_unambiguously_parsed")
        pending = [selected[0]]
        count = 0
        while pending:
            node = pending.pop()
            count += 1
            if count > 2000:
                raise _Unsupported("ast_budget_exceeded")
            pending.extend(child for _, child in node.children())
        return selected[0]

    def boolean(v):
        return v.bits != 0

    def relation(condition, defined):
        return value(z3.If(condition, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32)), defined=defined)

    def binary(op, a, b):
        # Unlike the usual arithmetic conversions, shifts take their result
        # type from the promoted LEFT operand (C11 6.5.7p3).
        unsigned = a.unsigned if op in ("<<", ">>") else a.unsigned or b.unsigned
        valid = z3.And(a.defined, b.defined)
        x, y = a.bits, b.bits
        if op in ("+", "-", "*"):
            bits = {"+": lambda: x+y, "-": lambda: x-y, "*": lambda: x*y}[op]()
            if not unsigned:
                wide_x, wide_y = z3.SignExt(32, x), z3.SignExt(32, y)
                wide = {"+": lambda: wide_x+wide_y, "-": lambda: wide_x-wide_y,
                        "*": lambda: wide_x*wide_y}[op]()
                valid = z3.And(valid, z3.SignExt(32, bits) == wide)
        elif op in ("/", "%"):
            valid = z3.And(valid, y != 0)
            if unsigned:
                bits = z3.UDiv(x, y) if op == "/" else z3.URem(x, y)
            else:
                valid = z3.And(valid, z3.Not(z3.And(x == 0x80000000, y == 0xffffffff)))
                bits = x/y if op == "/" else z3.SRem(x, y)
        elif op in ("&", "|", "^"):
            bits = {"&": lambda: x & y, "|": lambda: x | y, "^": lambda: x ^ y}[op]()
        elif op in ("<<", ">>"):
            valid = z3.And(valid, z3.ULT(y, 32))
            if op == "<<":
                bits = x << y
                if not unsigned:
                    wide = z3.SignExt(32,x) << z3.ZeroExt(32,y)
                    valid = z3.And(valid,x >= 0,z3.ULE(wide,0x7fffffff))
            else:
                bits = z3.LShR(x,y) if unsigned else x >> y
        elif op in ("==", "!=", "<", "<=", ">", ">="):
            operators = {"==": lambda: x == y, "!=": lambda: x != y,
                         "<": lambda: z3.ULT(x,y) if unsigned else x<y,
                         "<=": lambda: z3.ULE(x,y) if unsigned else x<=y,
                         ">": lambda: z3.UGT(x,y) if unsigned else x>y,
                         ">=": lambda: z3.UGE(x,y) if unsigned else x>=y}
            return relation(operators[op](), valid)
        elif op in ("&&", "||"):
            # C evaluates the right operand only when needed.
            needed = boolean(a) if op == "&&" else z3.Not(boolean(a))
            valid = z3.And(a.defined, z3.Implies(needed, b.defined))
            return relation(z3.And(boolean(a),boolean(b)) if op == "&&" else z3.Or(boolean(a),boolean(b)), valid)
        else:
            raise _Unsupported("unsupported_operator:" + op)
        return value(bits, unsigned, valid)

    def expression(node, env):
        if isinstance(node, c_ast.ID):
            if node.name not in env:
                raise _Unsupported("global_or_unknown_identifier")
            return env[node.name]
        if isinstance(node, c_ast.Constant):
            token = node.value
            if "l" in token.lower()[-2:]:
                raise _Unsupported("long_literal")
            digits = re.sub(r"[uU]+$", "", token)
            radix = 16 if digits.lower().startswith("0x") else 8 if len(digits)>1 and digits.startswith("0") else 10
            number = int(digits, radix)
            unsigned = token.lower().endswith("u") or (radix != 10 and number > 0x7fffffff)
            if not 0 <= number <= (0xffffffff if unsigned else 0x7fffffff):
                raise _Unsupported("literal_outside_integer32")
            return value(z3.BitVecVal(number,32), unsigned)
        if isinstance(node, c_ast.BinaryOp):
            return binary(node.op, expression(node.left,env), expression(node.right,env))
        if isinstance(node, c_ast.UnaryOp):
            operand = expression(node.expr,env)
            if node.op == "!": return relation(z3.Not(boolean(operand)), operand.defined)
            if node.op == "~": return value(~operand.bits,operand.unsigned,operand.defined)
            if node.op == "+": return operand
            if node.op == "-":
                valid = operand.defined if operand.unsigned else z3.And(operand.defined,operand.bits != 0x80000000)
                return value(-operand.bits,operand.unsigned,valid)
        if isinstance(node, c_ast.Cast):
            operand = expression(node.expr,env)
            return value(operand.bits,ctype(node.to_type.type),operand.defined)
        if isinstance(node, c_ast.TernaryOp):
            cond = expression(node.cond,env)
            yes, no = expression(node.iftrue,env), expression(node.iffalse,env)
            return value(z3.If(boolean(cond),yes.bits,no.bits),yes.unsigned or no.unsigned,
                         z3.And(cond.defined,z3.If(boolean(cond),yes.defined,no.defined)))
        raise _Unsupported("unsupported_expression:" + type(node).__name__)

    def signature(fn):
        if any(spec != "inline" for spec in fn.decl.funcspec):
            raise _Unsupported("function_specifier_not_modeled")
        params = fn.decl.type.args.params if fn.decl.type.args else []
        if len(params)==1 and isinstance(params[0],c_ast.Typename):
            if isinstance(params[0].type,c_ast.TypeDecl) and params[0].type.type.names == ["void"]:
                params = []
        if any(not isinstance(p,c_ast.Decl) or not p.name for p in params):
            raise _Unsupported("unsupported_parameter")
        if len({p.name for p in params}) != len(params):
            raise _Unsupported("duplicate_parameter_name")
        return ctype(fn.decl.type.type), [(p.name,ctype(p.type)) for p in params]

    def interpret(fn, params, arguments):
        terminals = []
        initial = ({name:value(arg,unsigned) for (name,unsigned),arg in zip(params,arguments)},z3.BoolVal(True),z3.BoolVal(True))
        steps = 0

        def statement(node, state):
            nonlocal steps
            steps += 1
            if steps > 2048 or len(terminals)>64:
                raise _Unsupported("path_budget_exceeded")
            env, path, valid = state
            if node is None or isinstance(node,c_ast.EmptyStatement): return [state]
            if isinstance(node,c_ast.Compound):
                outer_names = set(env)
                states = [state]
                for child in node.block_items or []:
                    states = [s for previous in states for s in statement(child,previous)]
                    if len(states)>64: raise _Unsupported("path_budget_exceeded")
                return [({key:val for key,val in scoped.items() if key in outer_names}, path, valid)
                        for scoped,path,valid in states]
            if isinstance(node,c_ast.Return):
                returned = expression(node.expr,env)
                terminals.append((path,z3.And(valid,returned.defined),returned.bits))
                return []
            if isinstance(node,c_ast.If):
                cond = expression(node.cond,env)
                guard = z3.And(valid,cond.defined)
                return (statement(node.iftrue,(dict(env),z3.And(path,boolean(cond)),guard)) +
                        statement(node.iffalse,(dict(env),z3.And(path,z3.Not(boolean(cond))),guard)))
            if isinstance(node,c_ast.Decl):
                if node.storage and node.storage != ["register"]:
                    raise _Unsupported("persistent_or_external_storage_not_modeled")
                if node.name in env: raise _Unsupported("shadowing_not_supported")
                unsigned = ctype(node.type)
                assigned = expression(node.init,env) if node.init else value(z3.BitVec("uninitialized_"+node.name,32),unsigned,z3.BoolVal(False))
                updated = dict(env)
                updated[node.name] = value(assigned.bits,unsigned,assigned.defined)
                return [(updated,path,z3.And(valid,assigned.defined) if node.init else valid)]
            if isinstance(node,c_ast.Assignment) and isinstance(node.lvalue,c_ast.ID):
                name = node.lvalue.name
                if name not in env: raise _Unsupported("global_write")
                assigned = expression(node.rvalue,env)
                if node.op != "=": assigned = binary(node.op[:-1],env[name],assigned)
                updated = dict(env)
                updated[name] = value(assigned.bits,env[name].unsigned,assigned.defined)
                return [(updated,path,z3.And(valid,assigned.defined))]
            raise _Unsupported("unsupported_statement:" + type(node).__name__)

        remaining = statement(fn.body,initial)
        if remaining or not terminals: raise _Unsupported("missing_return_or_unsupported_control_flow")
        return terminals

    try:
        original, reconstructed = parse(reference), parse(candidate,True)
        original_type, original_params = signature(original)
        candidate_type, candidate_params = signature(reconstructed)
        if (original_type,[p[1] for p in original_params]) != (candidate_type,[p[1] for p in candidate_params]):
            raise _Unsupported("abi_type_mismatch")
        args = [z3.BitVec(f"argument_{i}",32) for i in range(len(original_params))]
        left = interpret(original,original_params,args)
        right = interpret(reconstructed,candidate_params,args)
        left_defined = z3.Or(*[z3.And(path,valid) for path,valid,_ in left])
        right_defined = z3.Or(*[z3.And(path,valid) for path,valid,_ in right])
        def output(terms):
            returned = z3.BitVecVal(0,32)
            for path,_,bits in terms: returned = z3.If(path,bits,returned)
            return returned
        left_output, right_output = output(left),output(right)
        solver = z3.Solver()
        solver.set(timeout=timeout_ms,rlimit=500000,random_seed=0)
        solver.add(left_defined)
        domain = solver.check()
        if domain != z3.sat:
            raise _Unsupported("reference_domain_empty_or_unknown")
        solver.add(z3.Or(z3.Not(right_defined),left_output != right_output))
        checked = solver.check()
        result["reference_paths"] = len(left)
        result["candidate_paths"] = len(right)
        if checked == z3.unsat:
            result["status"] = "equivalent_in_model"
        elif checked == z3.sat:
            model = solver.model()
            def read(bits,unsigned):
                observed = model.eval(bits,model_completion=True)
                return observed.as_long() if unsigned else observed.as_signed_long()
            candidate_defined = z3.is_true(model.eval(right_defined,model_completion=True))
            witness = {"arguments":[read(arg,unsigned) for arg,(_,unsigned) in zip(args,original_params)],
                       "reference_return":read(left_output,original_type),
                       "candidate_return":read(right_output,candidate_type) if candidate_defined else None,
                       "candidate_defined":candidate_defined}
            result.update(status="different",counterexample=witness)
            digest = hashlib.sha256(json.dumps({"reference":result["reference_sha256"],"candidate":result["candidate_sha256"],"witness":witness},sort_keys=True).encode()).hexdigest()
            result["reproduction_id"] = "ce-"+digest
        else:
            result["reason"] = "solver_unknown:"+solver.reason_unknown()
    except Exception as exc:
        # Unsupported syntax, budgets and parser failures abstain. They can
        # never produce an equivalence claim or a fabricated percentage.
        result["reason"] = str(exc)[:200] or type(exc).__name__
    return result
