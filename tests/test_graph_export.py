from __future__ import annotations

from pathlib import Path
import pytest

from aether_re.graph_export import (
    SCHEMA,
    _clean_node_id,
    export_callgraph,
)


def test_clean_node_id():
    assert _clean_node_id("main") == "fn_main"
    assert _clean_node_id("sub_401000") == "fn_sub_401000"
    assert _clean_node_id("std::string::c_str") == "fn_std__string__c_str"


def test_export_callgraph_formats(tmp_path: Path):
    sample = tmp_path / "test_app.exe"
    # Binário com exportações/código observável
    sample.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00" + b"\x00" * 64 + b"kernel32.dll\x00ExitProcess\x00")

    # 1. Mermaid
    rep_mermaid = export_callgraph(sample, output_format="mermaid")
    assert rep_mermaid["schema"] == SCHEMA
    assert rep_mermaid["status"] == "complete"
    assert rep_mermaid["format"] == "mermaid"
    assert "flowchart TD" in rep_mermaid["graph_content"]

    # 2. Graphviz DOT
    rep_dot = export_callgraph(sample, output_format="dot")
    assert rep_dot["format"] == "dot"
    assert "digraph CallGraph" in rep_dot["graph_content"]

    # 3. JSON Graph
    rep_json = export_callgraph(sample, output_format="json")
    assert rep_json["format"] == "json"
    assert "source-graph.v1" in rep_json["graph_content"]


def test_export_callgraph_invalid_format(tmp_path: Path):
    sample = tmp_path / "app.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 32)
    with pytest.raises(ValueError, match="Formato não suportado"):
        export_callgraph(sample, output_format="unsupported_format_xyz")


def test_export_callgraph_missing_file_raises(tmp_path: Path):
    missing = tmp_path / "missing.exe"
    with pytest.raises(FileNotFoundError):
        export_callgraph(missing)
