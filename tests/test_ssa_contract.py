from aether_re.ssa_ir import lift_to_ssa_ir


def ins(block, mnemonic, operands):
    return {"block": block, "mnemonic": mnemonic, "op_str": operands}


def test_immediates_are_literals_and_self_copy_reads_previous_definition():
    report = lift_to_ssa_ir([ins("entry", "mov", "rax, 10"), ins("entry", "mov", "rax, rax")])
    first, second = report["ssa_instructions"]
    assert first["srcs"] == ["10"]
    assert second["srcs"] == [first["dest"]]
    assert second["dest"] != first["dest"]


def test_diamond_phi_has_distinct_predecessor_definitions_and_merge_use():
    report = lift_to_ssa_ir([
        ins("entry", "cmp", "rdi, 0"), ins("left", "mov", "rax, 11"),
        ins("right", "mov", "rax, 22"), ins("merge", "add", "rax, 1"),
    ], [("entry", "left"), ("entry", "right"), ("left", "merge"), ("right", "merge")])
    assert report["status"] == "complete"
    phi = next(p for p in report["phi_nodes"] if p["variable"] == "rax" and p["block"] == "merge")
    rows = {i["block"]: i for i in report["ssa_instructions"]}
    assert dict(zip(phi["predecessors"], phi["sources"])) == {"left": rows["left"]["dest"], "right": rows["right"]["dest"]}
    assert rows["merge"]["srcs"][0] == phi["dest"]
    assert len(set(phi["sources"])) == 2


def test_loop_phi_binds_entry_and_backedge_values():
    report = lift_to_ssa_ir([
        ins("entry", "mov", "rax, 0"), ins("head", "add", "rax, 1"), ins("exit", "ret", ""),
    ], [("entry", "head"), ("head", "head"), ("head", "exit")])
    phi = next(p for p in report["phi_nodes"] if p["variable"] == "rax")
    rows = {i["block"]: i for i in report["ssa_instructions"]}
    assert phi["block"] == "head"
    assert dict(zip(phi["predecessors"], phi["sources"])) == {"entry": rows["entry"]["dest"], "head": rows["head"]["dest"]}
    assert rows["head"]["srcs"][0] == phi["dest"]
    assert rows["exit"]["srcs"] == [rows["head"]["dest"]]


def test_join_without_competing_definitions_does_not_invent_phi_variable():
    report = lift_to_ssa_ir([ins("entry", "mov", "rax, 4"), ins("merge", "ret", "")],
        [("entry", "left"), ("entry", "right"), ("left", "merge"), ("right", "merge")])
    assert report["phi_nodes"] == []
    assert report["ssa_instructions"][1]["srcs"] == [report["ssa_instructions"][0]["dest"]]


def test_cfg_without_instruction_block_mapping_is_rejected():
    report = lift_to_ssa_ir([{"mnemonic":"mov","op_str":"rax, 1"}], [("entry","other")])
    assert report["status"] == "invalid"
    assert report["ssa_valid"] is False
    assert report["phi_nodes"] == []


def test_dead_predecessor_does_not_feed_reachable_phi():
    report = lift_to_ssa_ir([ins("entry","mov","rax, 1"),ins("dead","mov","rax, 9"),ins("merge","ret","")],
        [("entry","merge"),("dead","merge")])
    assert report["unreachable_blocks"] == ["dead"]
    assert report["phi_nodes"] == []
    assert [i["block"] for i in report["ssa_instructions"]] == ["entry","merge"]


def test_unknown_opcode_and_memory_are_explicitly_partial_without_fake_definitions():
    for opcode, operands in [("push", "rax"), ("mov", "[rax], rbx"), ("call", "external")]:
        report = lift_to_ssa_ir([ins("entry",opcode,operands)])
        assert report["status"] == "partial"
        assert report["ssa_valid"] is False
        assert report["ssa_instructions"][0]["dest"] is None
        assert report["unmodeled_instructions"] == [0]


def test_arithmetic_flags_reach_conditional_branch():
    report = lift_to_ssa_ir([ins("entry","add","rax, 1"),ins("entry","je","done")])
    arithmetic, branch = report["ssa_instructions"]
    assert branch["srcs"] == [arithmetic["flag_dest"]]


def test_input_liveins_are_explicit_and_no_definition_uses_itself():
    report = lift_to_ssa_ir([ins("entry","mov","rax, rbx")])
    row = report["ssa_instructions"][0]
    assert row["srcs"] == ["rbx_0"]
    assert report["live_in_values"] == ["rbx_0"]
    assert row["dest"] not in row["srcs"]


def test_mixed_register_alias_widths_abstain_from_complete_machine_state():
    report = lift_to_ssa_ir([ins("entry","mov","rax, 1"),ins("entry","mov","eax, 2")])
    assert report["status"] == "partial"
    assert "register_alias_overlap_not_modeled" in report["limitations"]


def test_indirect_branch_cannot_claim_complete_without_target_dependency():
    for target in ("rax", "[rax]"):
        report = lift_to_ssa_ir([ins("entry","mov","rax, rbx"),ins("entry","jmp",target)])
        assert report["status"] == "partial"
        assert report["ssa_valid"] is False
        assert report["unmodeled_instructions"] == [1]


def test_instructions_after_terminator_are_invalid():
    report = lift_to_ssa_ir([ins("entry","ret",""),ins("entry","mov","rax, 42"),ins("other","mov","rbx, rax")],
        [("entry","other")])
    assert report["status"] == "invalid"
    assert report["ssa_instructions"] == []


def test_return_block_cannot_have_outgoing_cfg_edge():
    report = lift_to_ssa_ir([ins("entry","ret","")],[("entry","other")])
    assert report["status"] == "invalid"


def test_explicit_branch_and_cfg_must_agree():
    report = lift_to_ssa_ir([ins("entry","jmp","wrong")],[("entry","actual")])
    assert report["status"] == "invalid"


def test_shift_cannot_destroy_prior_flags_when_zero_count_is_possible():
    report = lift_to_ssa_ir([ins("entry","cmp","rax, 1"),ins("entry","shl","rax, 0"),ins("entry","je","done")])
    assert report["status"] == "partial"
    assert report["ssa_valid"] is False


def test_non_x86_registers_are_not_silently_accepted_as_x86():
    report = lift_to_ssa_ir([ins("entry","mov","r0, 1")])
    assert report["status"] == "partial"


def test_malformed_comma_operands_cannot_be_normalized_into_valid_instruction():
    report = lift_to_ssa_ir([ins("entry","mov","rax,, 1")])
    assert report["status"] == "invalid"
