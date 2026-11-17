import pytest
from aether_re.ground_truth_eval import evaluate_decompilation_against_ground_truth


def evaluate(tmp_path, original, candidate):
    source = tmp_path / "reference.c"
    source.write_text(original, encoding="utf-8")
    return evaluate_decompilation_against_ground_truth(source, candidate, "calc")


def test_wrong_return_produces_a_behavioral_counterexample(tmp_path):
    result = evaluate(tmp_path, "int calc(int a, int b) { return a+b; }",
                      "int calc(int a, int b) { return 0; }")
    comparison = result["behavioral_comparison"]
    assert comparison["status"] == "different"
    witness = comparison["counterexample"]
    assert witness["reference_return"] != witness["candidate_return"]
    assert result["empirical_fidelity_score_pct"] is None


def test_unsigned_reassociation_is_verified_in_the_explicit_word_model(tmp_path):
    result = evaluate(tmp_path,
        "unsigned int calc(unsigned int a, unsigned int b) { return (a+b)+1u; }",
        "unsigned int calc(unsigned int x, unsigned int y) { return x+(y+1u); }")
    comparison = result["behavioral_comparison"]
    assert comparison["status"] == "equivalent_in_model"
    assert comparison["universal_proof"] is False
    assert comparison["model"] == "c_integer32_pure_functions"


def test_branch_change_has_a_reproducible_input(tmp_path):
    result = evaluate(tmp_path,
        "int calc(int a, int b) { if(a>b) return a; return b; }",
        "int calc(int a, int b) { if(a<b) return a; return b; }")
    assert result["behavioral_comparison"]["status"] == "different"
    assert result["behavioral_comparison"]["reproduction_id"].startswith("ce-")


def test_candidate_undefined_on_reference_defined_input_is_not_equivalent(tmp_path):
    result = evaluate(tmp_path, "int calc(int x) { return x; }",
                      "int calc(int x) { return x+1-1; }")
    comparison = result["behavioral_comparison"]
    assert comparison["status"] == "different"
    assert comparison["counterexample"]["candidate_defined"] is False
    assert comparison["counterexample"]["arguments"] == [2147483647]


@pytest.mark.parametrize("candidate", ["", "int other(void){return 0;}"])
def test_absent_target_or_candidate_never_gets_a_score(tmp_path, candidate):
    with pytest.raises(ValueError):
        evaluate(tmp_path, "int other(void) {return 0;}", candidate)


def test_empty_candidate_is_rejected_for_a_present_reference(tmp_path):
    with pytest.raises(ValueError):
        evaluate(tmp_path, "int calc(void) {return 0;}", "")


def test_unknown_callee_is_not_renamed_from_the_oracle(tmp_path):
    result = evaluate(tmp_path, "int calc(int x) { return known(x); }",
                      "int calc(int x) { return FUN_1234(x); }")
    assert result["preserved_calls"] == []
    assert result["call_preservation_rate_pct"] == 0
    assert result["behavioral_comparison"]["status"] == "unknown"


def test_memory_effects_are_not_certified_by_structural_similarity(tmp_path):
    result = evaluate(tmp_path, "void calc(int *p) {*p=1;}", "void calc(int *p) {*p=2;}")
    assert result["behavioral_comparison"]["status"] == "unknown"
    assert result["empirical_fidelity_score_pct"] is None


def test_loop_cutoff_is_unknown_not_equivalent(tmp_path):
    result = evaluate(tmp_path, "int calc(int x) {while(x>0)x--; return x;}",
                      "int calc(int x) {while(x>0)x--; return x;}")
    assert result["behavioral_comparison"]["status"] == "unknown"


def test_static_local_state_is_outside_the_pure_function_model(tmp_path):
    result = evaluate(tmp_path, "int calc(void){return 1;}",
                      "int calc(void){static int n=0;n+=1;return n;}")
    assert result["behavioral_comparison"]["status"] == "unknown"


@pytest.mark.parametrize("operator", ["<<", ">>"])
def test_unsigned_shift_count_does_not_change_the_left_operand_type(tmp_path, operator):
    result = evaluate(tmp_path,
        f"unsigned calc(unsigned x){{return x {operator} 1;}}",
        f"unsigned calc(unsigned x){{return ((int)x) {operator} 1u;}}")
    assert result["behavioral_comparison"]["status"] == "different"


def test_signed_left_shift_tracks_signed_result_overflow(tmp_path):
    result = evaluate(tmp_path, "unsigned calc(unsigned x){return x<<1;}",
                      "unsigned calc(unsigned x){return ((int)x)<<1;}")
    assert result["behavioral_comparison"]["status"] == "different"
    assert result["behavioral_comparison"]["counterexample"]["candidate_defined"] is False


def test_noreturn_contract_is_not_silently_ignored(tmp_path):
    result = evaluate(tmp_path,"int calc(int x){return x;}","_Noreturn int calc(int x){return x;}")
    assert result["behavioral_comparison"]["status"] == "unknown"


def test_block_local_cannot_be_read_after_its_scope_ends(tmp_path):
    result = evaluate(tmp_path,"int calc(void){return 1;}","int calc(void){{int y=1;}return y;}")
    assert result["behavioral_comparison"]["status"] == "unknown"
