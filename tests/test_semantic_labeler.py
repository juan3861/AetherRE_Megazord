from __future__ import annotations

import pytest
from aether_re.semantic_labeler import (
    enrich_callgraph_nodes,
    infer_function_role,
    is_anonymous_function_name,
)


def test_is_anonymous_function_name():
    assert is_anonymous_function_name("sub_401000") is True
    assert is_anonymous_function_name("fn_140001020") is True
    assert is_anonymous_function_name("0x401050") is True
    assert is_anonymous_function_name("main") is False
    assert is_anonymous_function_name("DllMain") is False


def test_infer_function_role_process_injection():
    res = infer_function_role(
        name="sub_401020",
        calls=["kernel32.dll:VirtualAllocEx", "kernel32.dll:WriteProcessMemory", "kernel32.dll:CreateRemoteThread"],
    )
    assert res["inferred_category"] == "process_injection"
    assert res["suggested_label"] == "sub_401020_injector"
    assert res["confidence"] >= 0.80


def test_infer_function_role_cryptography():
    res = infer_function_role(
        name="sub_402000",
        calls=["advapi32.dll:CryptEncrypt"],
        strings=["AES-256", "decrypt"],
    )
    assert res["inferred_category"] == "cryptography"
    assert res["suggested_label"] == "sub_402000_crypto"
    assert res["confidence"] >= 0.60


def test_infer_function_role_network_c2():
    res = infer_function_role(
        name="sub_403000",
        calls=["wininet.dll:InternetOpenA", "wininet.dll:HttpSendRequestA"],
        strings=["https://c2.example.com/beacon"],
    )
    assert res["inferred_category"] == "network_client"
    assert res["suggested_label"] == "sub_403000_net_c2"


def test_enrich_callgraph_nodes():
    nodes = {
        "entry_point": {"name": "entry_point", "confidence": 0.9},
        "sub_401020": {"name": "sub_401020", "confidence": 0.5},
        "ExitProcess": {"name": "ExitProcess", "confidence": 0.95},
    }
    edges = [
        ("entry_point", "sub_401020"),
        ("sub_401020", "ExitProcess"),
    ]
    enriched = enrich_callgraph_nodes(nodes, edges)
    assert len(enriched) == 3
    assert "suggested_label" in enriched["sub_401020"]
    assert "inferred_role" in enriched["sub_401020"]
