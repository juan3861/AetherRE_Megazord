import sys
import types
from pathlib import Path

from aether_re.adapters.angr import AngrAdapter


def test_angr_adapter_closes_runtime_database_before_return(tmp_path: Path, monkeypatch):
    state = {"cleaned": False}

    class FakeProject:
        def __init__(self, *_args, **_kwargs):
            self.arch = types.SimpleNamespace(name="AMD64")
            self.entry = 0x1000
            self.kb = types.SimpleNamespace(rtdb=types.SimpleNamespace(cleanup=lambda: state.update(cleaned=True)))
            self.analyses = types.SimpleNamespace(CFGFast=lambda **_kw: types.SimpleNamespace(functions={}))

    fake_angr = types.SimpleNamespace(Project=FakeProject)
    monkeypatch.setitem(sys.modules, "angr", fake_angr)
    monkeypatch.setattr(AngrAdapter, "available", lambda _self: True)

    result = AngrAdapter().analyze(Path("target.exe"), tmp_path)

    assert result["executed"] is True
    assert state["cleaned"] is True
    assert (tmp_path / "angr_report.json").is_file()
