from __future__ import annotations

from pathlib import Path

from aether_re import pipeline


class _UnavailableAdapter:
    def __init__(self, name: str) -> None:
        self.name = name

    def available(self) -> bool:
        return False


class _PartialGhidraAdapter:
    name = "ghidra"

    def __init__(self) -> None:
        self.calls: list[Path] = []

    def available(self) -> bool:
        return True

    def analyze(self, target: Path, out_dir: Path) -> dict[str, object]:
        # Static test double: read-only target handling; this never executes it.
        assert target.is_file()
        self.calls.append(target)
        decompiled_path = out_dir / "ghidra-partial.c"
        decompiled_path.write_text(
            "/* partial_pipeline_sentinel @ 0x401000 */\n"
            "int partial_pipeline_sentinel(void) { return 7; }\n",
            encoding="utf-8",
        )
        return {
            "ok": True,
            "executed": True,
            "produced_evidence": True,
            "partial": True,
            "extraction_status": "truncated",
            "truncated": True,
            "returncode": 0,
            "attempted_functions": 1,
            "exported_functions": 1,
            "failed_functions": 0,
            "max_functions": 1,
            "decompiled_path": str(decompiled_path),
        }


def test_partial_ghidra_pipeline_output_is_evidence_not_preferred_source(
    tmp_path: Path, monkeypatch
) -> None:
    fixture = Path(__file__).parents[1] / "samples" / "fixtures" / "notepad_reference.exe"
    assert fixture.is_file(), "the benign static PE fixture must be present"

    fake_ghidra = _PartialGhidraAdapter()
    monkeypatch.setattr(pipeline, "GhidraAdapter", lambda: fake_ghidra)
    for symbol, name in (
        ("RizinAdapter", "rizin"),
        ("FridaAdapter", "frida"),
        ("UnicornAdapter", "unicorn"),
        ("AngrAdapter", "angr"),
        ("BinaryNinjaAdapter", "binaryninja"),
    ):
        monkeypatch.setattr(
            pipeline,
            symbol,
            lambda name=name: _UnavailableAdapter(name),
        )

    report = pipeline.run_megazord(
        fixture,
        out_dir=tmp_path / "analysis",
        use_adapters=True,
        deep=False,
    )

    ghidra_result = report.adapter_results["ghidra"]
    assert len(fake_ghidra.calls) == 1
    assert fake_ghidra.calls[0].read_bytes() == fixture.read_bytes()
    assert "intake" in fake_ghidra.calls[0].parts
    assert ghidra_result["state"] == "partial"
    assert ghidra_result["partial"] is True
    assert ghidra_result["truncated"] is True

    ghidra_evidence = [item for item in report.function_evidence if item.source == "ghidra"]
    assert ghidra_evidence
    assert all(item.confidence <= 0.80 for item in ghidra_evidence)
    assert all(
        any("partial" in warning.lower() for warning in item.warnings)
        for item in ghidra_evidence
    )
    assert any("partial" in item.lower() for item in report.limitations)

    # A truncated Ghidra export must not replace the reconstruction output or
    # raise confidence to the complete-source path.
    assert "GHIDRA DECOMPILATION (preferida)" not in report.pseudo_source
    assert "partial_pipeline_sentinel" not in report.pseudo_source
    assert report.overall_confidence <= 0.80
