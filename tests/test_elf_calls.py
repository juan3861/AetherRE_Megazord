import pytest

from aether_re.engines.elf_calls import recover_direct_calls


def test_recover_direct_calls_is_static_and_resolves_local_x86_call():
    pytest.importorskip("capstone")
    # call 0x400010 from 0x400000, followed by padding and a one-byte helper.
    payload = b"\xe8\x0b\x00\x00\x00" + (b"\x90" * 11) + b"\xc3"
    structure = {
        "format": "ELF64",
        "machine_name": "x86_64",
        "sections": [{"name": ".text", "va": "0x400000", "offset": 0, "raw_size": len(payload), "chars": "0x6"}],
        "symbols": [
            {"name": "main", "value": "0x400000", "size": 5, "type": 2},
            {"name": "helper", "value": "0x400010", "size": 1, "type": 2},
        ],
    }
    report = recover_direct_calls(payload, structure)
    assert report["status"] == "measured"
    assert report["resolved_calls"] == 1
    assert report["unique_relations"] == [{"caller": "main", "callee": "helper"}]
    assert report["executed"] is False


def test_recover_direct_calls_does_not_score_stripped_binary_without_function_symbols():
    pytest.importorskip("capstone")
    payload = b"\xe8\x0b\x00\x00\x00" + (b"\x90" * 11) + b"\xc3"
    structure = {"format": "ELF64", "machine_name": "x86_64", "sections": [{"name": ".text", "va": "0x400000", "offset": 0, "raw_size": len(payload), "chars": "0x6"}], "symbols": []}
    report = recover_direct_calls(payload, structure)
    assert report["status"] == "not_measured"
    assert report["reason"] == "function_symbols_not_available"
    assert report["executed"] is False


def test_recover_direct_calls_does_not_infer_ranges_from_zero_sized_runtime_symbols():
    pytest.importorskip("capstone")
    payload = b"\xe8\x0b\x00\x00\x00" + (b"\x90" * 11) + b"\xc3"
    structure = {
        "format": "ELF64", "machine_name": "x86_64",
        "sections": [{"name": ".text", "va": "0x400000", "offset": 0, "raw_size": len(payload), "chars": "0x6"}],
        "symbols": [
            {"name": "register_tm_clones", "value": "0x400000", "size": 0, "type": 2},
            {"name": "frame_dummy", "value": "0x400010", "size": 0, "type": 2},
        ],
    }
    report = recover_direct_calls(payload, structure)
    assert report["status"] == "not_measured"
    assert report["reason"] == "function_symbols_not_available"


def test_recover_direct_calls_preserves_alias_ambiguity():
    pytest.importorskip("capstone")
    payload = b"\xe8\x0b\x00\x00\x00" + (b"\x90" * 11) + b"\xc3"
    structure = {
        "format": "ELF64",
        "machine_name": "x86_64",
        "sections": [{"name": ".text", "va": "0x400000", "offset": 0, "raw_size": len(payload), "chars": "0x6"}],
        "symbols": [
            {"name": "main", "value": "0x400000", "size": 5, "type": 2},
            {"name": "helper_a", "value": "0x400010", "size": 1, "type": 2},
            {"name": "helper_b", "value": "0x400010", "size": 1, "type": 2},
        ],
    }
    report = recover_direct_calls(payload, structure)
    assert report["status"] == "measured"
    assert report["resolved_calls"] == 0
    assert report["ambiguous_calls"] == 1
    assert report["unique_relations"] == []
