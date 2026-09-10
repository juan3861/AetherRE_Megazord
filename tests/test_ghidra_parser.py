from pathlib import Path

from aether_re.engines.ghidra_parse import parse_decompiled_file


FIXTURE = """/* FUN_140001008 @ 140001008 */

void FUN_140001008(void)
{
  return helper("ok");
}

/* WARNED @ 140001020 */

/* WARNING: Injection replacement */

void WARNED(void)
{
  return 42;
}
"""


def test_parse_existing_fixture(tmp_path: Path):
    path = tmp_path / "decompiled.c"
    path.write_text(FIXTURE, encoding="utf-8")
    functions = parse_decompiled_file(path)
    assert len(functions) == 2
    assert functions[0]["address"] == "0x140001008"
    assert functions[0]["calls"] == ["helper"]
    assert functions[1]["warnings"] == ["Injection replacement"]
