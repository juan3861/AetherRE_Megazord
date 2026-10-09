from argparse import Namespace
from pathlib import Path

import megazord


def test_selftest_supplies_the_complete_analyze_namespace(monkeypatch):
    captured = None

    def fake_analyze(args: Namespace) -> int:
        nonlocal captured
        captured = args
        return 0

    monkeypatch.setattr(megazord, "cmd_analyze", fake_analyze)

    assert megazord.cmd_selftest(Namespace()) == 0
    assert captured is not None
    assert captured.reuse_cache is False
    assert captured.profile is None


def test_selftest_uses_a_fresh_scoped_output_for_each_run(monkeypatch):
    outputs = []

    def fake_analyze(args: Namespace) -> int:
        outputs.append(Path(args.out))
        return 0

    monkeypatch.setattr(megazord, "cmd_analyze", fake_analyze)

    assert megazord.cmd_selftest(Namespace()) == 0
    assert megazord.cmd_selftest(Namespace()) == 0

    expected_parent = (megazord.ROOT / "output" / "selftest").resolve()
    assert len(set(outputs)) == 2
    assert all(path.parent.resolve() == expected_parent for path in outputs)
    assert all(path.name.startswith("run-") for path in outputs)

