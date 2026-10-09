import json
from pathlib import Path

import pytest

from tools.juliet_multifile_corpus import materialize_multifile_corpus


def test_multifile_generator_copies_context_and_derives_conservative_relations(tmp_path: Path):
    v1 = tmp_path / "v1"
    support = tmp_path / "support"
    out = tmp_path / "v2"
    (v1 / "demo" / "src").mkdir(parents=True)
    support.mkdir()
    (v1 / "LICENSE").write_text("CC0", encoding="utf-8")
    (v1 / "README.upstream.md").write_text("upstream", encoding="utf-8")
    (v1 / "demo" / "src" / "main.c").write_text(
        "int bad_flow(void); int good_flow(void); int main(void) { bad_flow(); good_flow(); return 0; }",
        encoding="utf-8",
    )
    (v1 / "oracles").mkdir()
    (v1 / "oracles" / "demo.json").write_text(
        json.dumps({"expected_symbols": ["bad_flow", "good_flow"]}),
        encoding="utf-8",
    )
    (v1 / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "re-megazord-corpus.v1",
                "projects": [
                    {
                        "id": "demo",
                        "family": "demo-family",
                        "source": "demo/src/main.c",
                        "oracle": "oracles/demo.json",
                        "provenance": {"upstream_source": "fixture"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    for name in ("io.c", "std_testcase.h", "std_testcase_io.h", "std_thread.c", "std_thread.h"):
        (support / name).write_text(name, encoding="utf-8")

    manifest = materialize_multifile_corpus(v1, support, out)
    project = manifest["projects"][0]
    assert project["build_sources"] == ["demo/src/main.c", "demo/support/io.c", "demo/support/std_thread.c"]
    assert len(project["artifacts"]) == 6
    assert (out / "demo" / "support" / "std_thread.h").is_file()
    oracle = json.loads((out / project["oracle"]).read_text(encoding="utf-8"))
    assert oracle["expected_relations"] == [["main", "bad_flow"], ["main", "good_flow"]]
    assert len(json.loads((out / "demo" / "compile_commands.json").read_text(encoding="utf-8"))) == 3
    with pytest.raises(FileExistsError):
        materialize_multifile_corpus(v1, support, out)
