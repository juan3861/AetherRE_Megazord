from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from aether_re.semantic_deobfuscator import (
    deobfuscate_javascript_snippet,
    infer_identifier_semantics,
    is_minified_identifier,
    synthesize_typescript_interface,
)


def test_is_minified_identifier():
    assert is_minified_identifier("a") is True
    assert is_minified_identifier("et") is True
    assert is_minified_identifier("Dt") is True
    assert is_minified_identifier("sub_140001000") is True
    assert is_minified_identifier("fn_401020") is True
    assert is_minified_identifier("field_0x18") is True
    assert is_minified_identifier("validateCurrentWorkingDirectory") is False
    assert is_minified_identifier("parseCliOptions") is False


def test_infer_identifier_semantics_directory_validator():
    res = infer_identifier_semantics(
        "et",
        context_strings=["ENOENT", "The current directory no longer exists"],
        context_calls=["process.cwd"],
    )
    assert res["inferred_role"] == "directory_validator"
    assert res["suggested_name"] == "validateDirectory"
    assert res["confidence"] >= 0.90


def test_infer_identifier_semantics_debug_flags():
    res = infer_identifier_semantics(
        "it",
        context_strings=["--debug", "--debug-file"],
        context_calls=["startsWith"],
    )
    assert res["inferred_role"] == "debug_flag_checker"
    assert res["suggested_name"] == "isOnlyDebugFlags"
    assert res["confidence"] >= 0.90


def test_synthesize_typescript_interface():
    fields = {
        "permissionMode": "string | undefined",
        "model": "string | undefined",
        "allowBypass": "boolean",
    }
    ts = synthesize_typescript_interface("ParsedCliOptions", fields)
    assert "export interface ParsedCliOptions {" in ts
    assert "permissionMode?: string;" in ts
    assert "allowBypass: boolean;" in ts


def test_deobfuscate_javascript_snippet():
    minified = (
        'function et(a){ if(a === "ENOENT") { process.cwd(); } return false; }\n'
        'function it(t){ if(t === "--debug") { return true; } return false; }\n'
        'let res = et("ENOENT"); let d = it("--debug");'
    )
    res = deobfuscate_javascript_snippet(minified)
    assert res["functions_renamed"] == 2
    assert "validateDirectory" in res["deobfuscated_code"]
    assert "isOnlyDebugFlags" in res["deobfuscated_code"]
    assert "validateDirectory(" in res["deobfuscated_code"]
    assert "isOnlyDebugFlags(" in res["deobfuscated_code"]
