from aether_re.ctree_structuring import structure_control_flow

import pytest


def block(statements=(), **terminator):
    return {"statements":list(statements), "terminator":terminator}


@pytest.mark.parametrize("literal", [r'"\x4" "1"', r'"\1" "2"'])
def test_adjacent_string_tokens_preserve_escape_boundaries(literal):
    report = recover({"entry":block([f"puts({literal});"],kind="return",value="0")}, [],
                     declarations=("int puts(const char *message);",))
    assert report["status"] == "complete"
    assert literal in report["structured_c_source"]


def test_c11_trigraphs_are_processed_before_comment_line_splicing():
    report = recover({"entry":block(["// disabled effect ??/\nr += 1000;"],kind="return",value="r")}, [])
    assert report["status"] == "complete"
    assert "1000" not in report["structured_c_source"]


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_physical_line_endings_terminate_line_comments(newline):
    semantics,edges = diamond()
    semantics["entry"]["terminator"]["condition"] = "x // comment" + newline + " > 0"
    report = recover(semantics,edges)
    assert report["status"] == "complete"
    assert "if (x > 0)" in report["structured_c_source"]


@pytest.mark.parametrize("literal,expected", [
    ('"?" "?/n"', r'"\?" "\?/n"'),
    ('"?\\\n?="', r'"\?\?="'),
    ('"??="', '"#"'),
])
def test_literal_normalization_does_not_introduce_or_repeat_trigraph_translation(literal,expected):
    report = recover({"entry":block([f"puts({literal});"],kind="return",value="0")}, [],
                     declarations=("int puts(const char *message);",))
    assert report["status"] == "complete"
    assert expected in report["structured_c_source"]


def diamond():
    semantics={
        "entry":block(["r = x;"],kind="branch",condition="x > 0",true="left",false="right"),
        "left":block(["r += 7;"],kind="jump",target="join"),
        "right":block(["r -= 3;"],kind="jump",target="join"),
        "join":block(["r *= 2;"],kind="return",value="r"),
    }
    return semantics,[("entry","left"),("entry","right"),("left","join"),("right","join")]


def recover(semantics,edges,signature="int recovered(int x)",declarations=("int r = 0;",),**kwargs):
    return structure_control_flow(list(semantics),edges,{},[],"entry",
        block_semantics=semantics,function_signature=signature,declarations=declarations,**kwargs)


def test_cfg_without_effects_and_predicates_cannot_publish_placeholder_source():
    report=structure_control_flow(["entry","a","b"],[("entry","a"),("entry","b")],{},[],"entry")
    assert report["status"] == "incomplete"
    assert report["structured_c_source"] is None
    assert report["goto_elimination_rate_pct"] is None
    assert report["natural_loops_structured"] == 0


def test_diamond_preserves_predicate_effects_and_executes_shared_join_once():
    semantics,edges=diamond()
    report=recover(semantics,edges)
    assert report["status"] == "complete"
    assert report["strategy"] == "structured_regions"
    source=report["structured_c_source"]
    assert "if (x > 0)" in source
    assert source.count("r *= 2;") == 1
    assert "r += 7;" in source and "r -= 3;" in source
    assert report["gotos_remaining"] == 0
    assert report["c_syntax_checked"] is True
    assert set(report["emitted_blocks"]) == set(semantics)
    assert report["semantic_equivalence_proved"] is False


def test_header_effect_is_inside_loop_before_real_exit_predicate():
    semantics={
        "entry":block(kind="jump",target="head"),
        "head":block(["i++;"],kind="branch",condition="i < 4",true="body",false="exit"),
        "body":block(["r += i;"],kind="jump",target="head"),
        "exit":block(kind="return",value="r"),
    }
    edges=[("entry","head"),("head","body"),("head","exit"),("body","head")]
    report=recover(semantics,edges,"int recovered(void)",("int i = 0;","int r = 0;"))
    assert report["strategy"] == "structured_regions"
    source=report["structured_c_source"]
    assert source.index("while (") < source.index("i++;") < source.index("i < 4")
    assert "break;" in source
    assert report["natural_loops_structured"] == 1
    assert source.count("r += i;") == 1


def test_loop_break_and_continue_preserve_boundary_transfers():
    semantics={
        "entry":block(kind="jump",target="head"),
        "head":block(kind="branch",condition="i < 5",true="body",false="exit"),
        "body":block(["i++;"],kind="branch",condition="i == 2",true="head",false="add"),
        "add":block(["r += i;"],kind="branch",condition="i == 4",true="exit",false="head"),
        "exit":block(kind="return",value="r"),
    }
    edges=[("entry","head"),("head","body"),("head","exit"),("body","head"),("body","add"),("add","exit"),("add","head")]
    report=recover(semantics,edges,"int recovered(void)",("int i = 0;","int r = 0;"))
    assert report["strategy"] == "structured_regions"
    assert "continue;" in report["structured_c_source"]
    assert "break;" in report["structured_c_source"]
    assert report["gotos_remaining"] == 0


def test_switch_uses_declared_case_values_and_shared_join():
    semantics={
        "entry":block(kind="switch",expression="x",cases=[{"value":7,"target":"a"},{"value":19,"target":"b"}],default="c"),
        "a":block(["r = 1;"],kind="jump",target="join"),
        "b":block(["r = 2;"],kind="jump",target="join"),
        "c":block(["r = 3;"],kind="jump",target="join"),
        "join":block(kind="return",value="r"),
    }
    edges=[("entry","a"),("entry","b"),("entry","c"),("a","join"),("b","join"),("c","join")]
    report=recover(semantics,edges)
    assert report["strategy"] == "structured_regions"
    assert "case 7:" in report["structured_c_source"]
    assert "case 19:" in report["structured_c_source"]
    assert report["structured_c_source"].count("return r;") == 1


def irreducible():
    semantics={
        "entry":block(kind="branch",condition="x > 0",true="a",false="b"),
        "a":block(["r += 1;","x--;"],kind="branch",condition="x > 0",true="b",false="exit"),
        "b":block(["r += 10;","x--;"],kind="branch",condition="x > 0",true="a",false="exit"),
        "exit":block(kind="return",value="r"),
    }
    return semantics,[("entry","a"),("entry","b"),("a","b"),("a","exit"),("b","a"),("b","exit")]


def test_irreducible_flow_keeps_explicit_transfers_and_all_effects():
    semantics,edges=irreducible()
    report=recover(semantics,edges)
    assert report["status"] == "complete"
    assert report["is_reducible"] is False
    assert report["strategy"] == "explicit_cfg"
    assert report["gotos_remaining"] > 0
    assert report["goto_elimination_rate_pct"] < 100
    assert set(report["emitted_blocks"]) == set(semantics)
    assert "r += 1;" in report["structured_c_source"] and "r += 10;" in report["structured_c_source"]


def test_missing_reachable_semantics_is_incomplete():
    semantics,edges=diamond()
    nodes=list(semantics)
    del semantics["left"]
    report=structure_control_flow(nodes,edges,{},[],"entry",block_semantics=semantics,function_signature="int recovered(int x)",declarations=["int r;"])
    assert report["status"] == "incomplete"
    assert report["structured_c_source"] is None


def test_edges_and_terminator_disagreement_is_invalid():
    semantics,edges=diamond()
    semantics["entry"]["terminator"]["true"]="join"
    report=recover(semantics,edges)
    assert report["status"] == "invalid"
    assert report["structured_c_source"] is None


def test_statements_cannot_smuggle_unrepresented_control_flow():
    semantics,edges=diamond()
    semantics["left"]["statements"]=["if(x) return 999;"]
    report=recover(semantics,edges)
    assert report["status"] == "invalid"
    assert report["structured_c_source"] is None


def test_edge_order_does_not_assign_true_and_false_polarity():
    semantics,edges=diamond()
    assert recover(semantics,edges)["structured_c_source"] == recover(semantics,list(reversed(edges)))["structured_c_source"]


def test_unreachable_effects_are_reported_and_never_emitted():
    semantics,edges=diamond()
    semantics["dead"]=block(["dangerous_call();"],kind="return",value="99")
    report=recover(semantics,edges)
    assert report["unreachable_blocks"] == ["dead"]
    assert "dangerous_call" not in report["structured_c_source"]


def test_supplied_loop_hints_cannot_force_false_reducibility():
    semantics,edges=irreducible()
    report=structure_control_flow(list(semantics),edges,{"a":"entry","b":"a"},[{"header":"a","nodes":["a","b"]}],"entry",
        block_semantics=semantics,function_signature="int recovered(int x)",declarations=["int r = 0;"])
    assert report["is_reducible"] is False
    assert report["strategy"] == "explicit_cfg"
    assert report["analysis_hints_verified"] is False


def test_node_budget_is_enforced_before_building_output():
    report=structure_control_flow([f"b{i}" for i in range(257)],[],{},[],"b0")
    assert report["status"] == "invalid"
    assert report["structured_c_source"] is None


def test_infinite_cfg_does_not_invent_return_or_erase_backedge():
    semantics={"entry":block(["r++;"],kind="jump",target="entry")}
    report=recover(semantics,[("entry","entry")],"void recovered(void)",("int r = 0;",))
    assert report["strategy"] == "explicit_cfg"
    assert report["gotos_remaining"] > 0
    assert "return" not in report["structured_c_source"]


def test_return_value_must_agree_with_void_signature():
    report=recover({"entry":block(kind="return",value="1")},[],"void recovered(void)",())
    assert report["status"] == "invalid"


def test_duplicate_switch_values_are_invalid():
    semantics={"entry":block(kind="switch",expression="x",cases=[{"value":1,"target":"exit"},{"value":1,"target":"exit"}],default="exit"),
               "exit":block(kind="return",value="1")}
    assert recover(semantics,[("entry","exit")])["status"] == "invalid"


def test_condition_side_effect_is_kept_as_expression_not_replaced_by_constant():
    semantics,edges=diamond()
    semantics["entry"]["terminator"]["condition"]="++x > 0"
    report=recover(semantics,edges)
    from pycparser import c_ast, c_parser
    tree=c_parser.CParser().parse(report["structured_c_source"])
    condition=next(n.cond for n in tree.ext[0].body.block_items if isinstance(n,c_ast.If))
    assert isinstance(condition,c_ast.BinaryOp) and condition.op == ">"
    assert isinstance(condition.left,c_ast.UnaryOp) and condition.left.op == "++"
    assert condition.left.expr.name == "x"


def test_compound_literal_lifetime_is_not_shortened_by_added_branch_scope():
    semantics={
        "entry":block(kind="branch",condition="x > 0",true="left",false="right"),
        "left":block(["p = (int[]){7};"],kind="jump",target="join"),
        "right":block(["p = (int[]){9};"],kind="jump",target="join"),
        "join":block(kind="return",value="*p"),
    }
    edges=[("entry","left"),("entry","right"),("left","join"),("right","join")]
    report=recover(semantics,edges,declarations=("int *p;",))
    assert report["strategy"] == "explicit_cfg"
    assert report["fallback_reason"] == "scope_sensitive_c_requires_explicit_cfg"
    assert report["status"] == "complete"


def test_hash_and_comment_markers_inside_c_string_remain_literal_data():
    semantics={"entry":block(['puts("a#b // literal /* text */");'],kind="return",value="1")}
    report=recover(semantics,[],declarations=("int puts(const char *message);",))
    assert report["status"] == "complete"
    assert '"a#b // literal /* text */"' in report["structured_c_source"]


def test_decompiler_comments_are_removed_without_changing_tokens_or_effects():
    semantics,edges=diamond()
    semantics["entry"]["terminator"]["condition"]="x /* predicate */ > 0"
    semantics["left"]["statements"]=["r /* operand */ += 7; // observed effect"]
    report=recover(semantics,edges)
    assert report["status"] == "complete"
    assert "if (x > 0)" in report["structured_c_source"]
    assert "r += 7;" in report["structured_c_source"]


def test_backslash_newline_is_spliced_before_single_line_comment_removal():
    semantics={"entry":block(["// disabled effect \\\nr += 1000;"],kind="return",value="r")}
    report=recover(semantics,[])
    assert report["status"] == "complete"
    assert "1000" not in report["structured_c_source"]


def test_backslash_newline_in_literal_keeps_c_translation_value():
    semantics={"entry":block(['puts("ab\\\n#cd");'],kind="return",value="1")}
    report=recover(semantics,[],declarations=("int puts(const char *message);",))
    assert report["status"] == "complete"
    assert '"ab#cd"' in report["structured_c_source"]
