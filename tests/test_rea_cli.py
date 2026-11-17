import sys
from pathlib import Path

import pytest

import megazord


@pytest.mark.parametrize(
    ("state", "expected_code"),
    [("succeeded", 0), ("partial", 2), ("failed", 2)],
)
def test_rea_js_analyze_cli_routes_to_adapter(tmp_path, monkeypatch, capsys, state, expected_code):
    target = tmp_path / "app"
    out = tmp_path / "new-report"
    calls = []

    class FakeAdapter:
        def analyze(self, supplied_target: Path, supplied_out: Path):
            calls.append((supplied_target, supplied_out))
            return {"state": state, "ok": state == "succeeded", "produced_evidence": state == "succeeded"}

    if not hasattr(megazord, "ReaStaticJavaScriptAdapter"):
        pytest.fail("rea_js_cli_adapter_not_imported")
    monkeypatch.setattr(megazord, "ReaStaticJavaScriptAdapter", FakeAdapter)
    monkeypatch.setattr(sys, "argv", ["megazord.py", "rea-js-analyze", str(target), "--out", str(out)])

    result = megazord.main()

    assert result == expected_code
    assert calls == [(target, out)]
    assert "REA static JS" in capsys.readouterr().out


def test_universal_cli_explicit_js_electron_profile_routes_to_rea(tmp_path, monkeypatch, capsys):
    target = tmp_path / "app"
    out = tmp_path / "new-report"
    calls = []

    class FakeAdapter:
        def analyze(self, supplied_target: Path, supplied_out: Path):
            calls.append((supplied_target, supplied_out))
            return {"state": "succeeded", "ok": True, "produced_evidence": True, "evidence_sha256": "a" * 64}

    monkeypatch.setattr(megazord, "ReaStaticJavaScriptAdapter", FakeAdapter)
    monkeypatch.setattr(
        sys,
        "argv",
        ["megazord.py", "universal", str(target), "--out", str(out), "--profile", "js-electron"],
    )

    result = megazord.main()

    assert result == 0
    assert calls == [(target, out)]
    assert "profile=js-electron" in capsys.readouterr().out
